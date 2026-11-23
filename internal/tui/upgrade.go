package tui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ghostframe/internal/server"
)

// CurrentVersion is the canonical release identifier compiled into server & TUI binaries (overridable via -ldflags -X).
var CurrentVersion = "v4.2.0"

const (
	defaultGitHubAPIBase   = "https://api.github.com"
	defaultGitHubWebBase   = "https://github.com"
	defaultTargetBinary    = "/opt/kestrel/kestrel-server"
	defaultSystemdUnit     = "/etc/systemd/system/kestrel.service"
	maxUpgradeBinarySize   = 128 << 20 // 128 MiB safety cap
	minUpgradeDiskFreeByte = 64 << 20  // 64 MiB free space preflight
)

// ReleaseInfo describes a resolved GitHub Release target and its verification assets.
type ReleaseInfo struct {
	TagName      string
	AssetName    string
	BinaryURL    string
	ChecksumURL  string
	PublishedAt  string
	ReleaseNotes string
	ViaRedirect  bool
}

// BackupInfo describes an on-disk previous server binary available for instant rollback.
type BackupInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
	Banner  string
}

// RollbackResult summarizes a restored binary rollback.
type RollbackResult struct {
	FromVersion     string
	RestoredBanner  string
	BackupPath      string
	PreRollbackPath string
}

// UpgradeOptions parameterizes OTA self-upgrade/rollback and allows deterministic unit testing.
type UpgradeOptions struct {
	TargetVersion string // "" or "latest" queries GitHub latest release; explicit tag downloads directly
	MirrorPrefix  string // optional proxy/mirror prefix (e.g. "https://ghfast.top/")
	Force         bool   // reinstall even when remote tag matches CurrentVersion
	TargetBinary  string // default "/opt/ghostframe/gft-server"
	Repo          string // default ReleaseRepo
	Arch          string // default runtime.GOARCH
	APIBaseURL    string // default "https://api.github.com"
	WebBaseURL    string // default "https://github.com"
	HTTPClient    *http.Client
	RestartFn     func() error
	ActiveFn      func() bool
	PortProbeFn   func(port int) error
	ListenPort    int
	VerifyBinFn   func(path string) (string, error)
	ProgressFn    func(msg string)
	SkipLock      bool
	SkipDiskCheck bool
}

// UpgradeResult summarizes a completed or skipped OTA upgrade.
type UpgradeResult struct {
	FromVersion    string
	ToVersion      string
	AlreadyLatest  bool
	AssetName      string
	SHA256         string
	BackupPath     string
	VerifiedBanner string
}

func applyMirrorURL(mirror, rawURL string) string {
	m := strings.TrimSpace(mirror)
	if m == "" {
		return rawURL
	}
	return strings.TrimRight(m, "/") + "/" + strings.TrimLeft(rawURL, "/")
}

func normalizeVersionTag(v string) string {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "kestrel-server ")
	s = strings.TrimPrefix(s, "gft-server ")
	return strings.TrimSpace(s)
}

func summarizeReleaseNotes(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var kept []string
	totalRunes := 0
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		r := []rune(t)
		if totalRunes+len(r) > 360 {
			rem := 360 - totalRunes
			if rem > 3 {
				kept = append(kept, string(r[:rem-3])+"...")
			}
			break
		}
		kept = append(kept, t)
		totalRunes += len(r)
		if len(kept) >= 6 {
			break
		}
	}
	return strings.Join(kept, "\n")
}

func (c *Controller) resolveUpgradeOptions(opts UpgradeOptions) (UpgradeOptions, int) {
	if strings.TrimSpace(opts.Repo) == "" {
		opts.Repo = ReleaseRepo
	}
	if strings.TrimSpace(opts.Arch) == "" {
		opts.Arch = runtime.GOARCH
	}
	if strings.TrimSpace(opts.TargetBinary) == "" {
		opts.TargetBinary = defaultTargetBinary
	}
	if strings.TrimSpace(opts.MirrorPrefix) == "" {
		if m := strings.TrimSpace(os.Getenv("KSL_MIRROR")); m != "" {
			opts.MirrorPrefix = m
		} else {
			opts.MirrorPrefix = strings.TrimSpace(os.Getenv("GFT_MIRROR"))
		}
	}
	if strings.TrimSpace(opts.APIBaseURL) == "" {
		opts.APIBaseURL = defaultGitHubAPIBase
	} else {
		opts.APIBaseURL = strings.TrimRight(opts.APIBaseURL, "/")
	}
	if strings.TrimSpace(opts.WebBaseURL) == "" {
		opts.WebBaseURL = defaultGitHubWebBase
	} else {
		opts.WebBaseURL = strings.TrimRight(opts.WebBaseURL, "/")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{}
	}
	if opts.RestartFn == nil {
		opts.RestartFn = c.Tx.RestartFn
	}
	if opts.ActiveFn == nil {
		opts.ActiveFn = c.Tx.ActiveFn
	}
	if opts.PortProbeFn == nil {
		opts.PortProbeFn = c.Tx.PortProbeFn
	}
	if opts.VerifyBinFn == nil {
		opts.VerifyBinFn = defaultVerifyBinary
	}
	if opts.ProgressFn == nil {
		opts.ProgressFn = func(msg string) {
			c.printf("%s\n", msg)
		}
	}

	port := opts.ListenPort
	if port <= 0 && c.CfgPath != "" {
		if cfg, err := server.LoadConfig(c.CfgPath); err == nil {
			port = ConfigListenPort(cfg.Listen)
		}
	}
	return opts, port
}

func resolveReleaseQueryOptions(opts UpgradeOptions) UpgradeOptions {
	if strings.TrimSpace(opts.Repo) == "" {
		opts.Repo = ReleaseRepo
	}
	if strings.TrimSpace(opts.Arch) == "" {
		opts.Arch = runtime.GOARCH
	}
	if strings.TrimSpace(opts.MirrorPrefix) == "" {
		if m := strings.TrimSpace(os.Getenv("KSL_MIRROR")); m != "" {
			opts.MirrorPrefix = m
		} else {
			opts.MirrorPrefix = strings.TrimSpace(os.Getenv("GFT_MIRROR"))
		}
	}
	if strings.TrimSpace(opts.APIBaseURL) == "" {
		opts.APIBaseURL = defaultGitHubAPIBase
	} else {
		opts.APIBaseURL = strings.TrimRight(opts.APIBaseURL, "/")
	}
	if strings.TrimSpace(opts.WebBaseURL) == "" {
		opts.WebBaseURL = defaultGitHubWebBase
	} else {
		opts.WebBaseURL = strings.TrimRight(opts.WebBaseURL, "/")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{}
	}
	return opts
}

// CheckLatestRelease resolves release metadata via GitHub Releases API, falling back
// to the web /releases/latest 302 redirect if the REST API is rate-limited or unreachable.
func CheckLatestRelease(ctx context.Context, opts UpgradeOptions) (*ReleaseInfo, error) {
	opts = resolveReleaseQueryOptions(opts)
	assetName := fmt.Sprintf("kestrel-server-linux-%s", opts.Arch)
	target := strings.TrimSpace(opts.TargetVersion)

	if target != "" && !strings.EqualFold(target, "latest") {
		baseDL := fmt.Sprintf("%s/%s/releases/download/%s", opts.WebBaseURL, opts.Repo, target)
		return &ReleaseInfo{
			TagName:     target,
			AssetName:   assetName,
			BinaryURL:   applyMirrorURL(opts.MirrorPrefix, baseDL+"/"+assetName),
			ChecksumURL: applyMirrorURL(opts.MirrorPrefix, baseDL+"/checksums.txt"),
		}, nil
	}

	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", opts.APIBaseURL, opts.Repo)
	rel, apiErr := fetchReleaseFromAPI(ctx, opts.HTTPClient, apiURL, assetName, opts.MirrorPrefix)
	if apiErr == nil {
		return rel, nil
	}

	rawLatestURL := fmt.Sprintf("%s/%s/releases/latest", opts.WebBaseURL, opts.Repo)
	rel, redirErr := fetchReleaseFromRedirect(ctx, opts.HTTPClient, opts.WebBaseURL, opts.Repo, assetName, opts.MirrorPrefix, rawLatestURL)
	if redirErr == nil {
		return rel, nil
	}

	return nil, fmt.Errorf("release check failed (api: %v; redirect: %v)", apiErr, redirErr)
}

func fetchReleaseFromAPI(ctx context.Context, client *http.Client, apiURL, assetName, mirror string) (*ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+CurrentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var payload struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Body        string `json:"body"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.TagName) == "" {
		return nil, errors.New("empty tag_name in release API response")
	}

	var binURL, sumURL string
	for _, a := range payload.Assets {
		switch a.Name {
		case assetName:
			binURL = a.URL
		case "checksums.txt":
			sumURL = a.URL
		}
	}
	if binURL == "" || sumURL == "" {
		return nil, fmt.Errorf("release %s missing %s or checksums.txt", payload.TagName, assetName)
	}

	return &ReleaseInfo{
		TagName:      strings.TrimSpace(payload.TagName),
		AssetName:    assetName,
		BinaryURL:    applyMirrorURL(mirror, binURL),
		ChecksumURL:  applyMirrorURL(mirror, sumURL),
		PublishedAt:  strings.TrimSpace(payload.PublishedAt),
		ReleaseNotes: summarizeReleaseNotes(payload.Body),
	}, nil
}

func fetchReleaseFromRedirect(ctx context.Context, baseClient *http.Client, webBase, repo, assetName, mirror, rawLatestURL string) (*ReleaseInfo, error) {
	noFollow := *baseClient
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	candidates := []string{rawLatestURL}
	if strings.TrimSpace(mirror) != "" {
		candidates = []string{applyMirrorURL(mirror, rawLatestURL), rawLatestURL}
	}

	var lastErr error
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Kestrel-Updater/"+CurrentVersion)
		resp, err := noFollow.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()

		loc := resp.Header.Get("Location")
		tag := extractTagFromLocation(loc)
		if tag == "" && resp.Request != nil && resp.Request.URL != nil {
			tag = extractTagFromLocation(resp.Request.URL.String())
		}
		if tag != "" {
			baseDL := fmt.Sprintf("%s/%s/releases/download/%s", webBase, repo, tag)
			return &ReleaseInfo{
				TagName:     tag,
				AssetName:   assetName,
				BinaryURL:   applyMirrorURL(mirror, baseDL+"/"+assetName),
				ChecksumURL: applyMirrorURL(mirror, baseDL+"/checksums.txt"),
				ViaRedirect: true,
			}, nil
		}
		lastErr = fmt.Errorf("redirect probe %s returned status %d without /releases/tag/ location", u, resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = errors.New("redirect probe failed")
	}
	return nil, lastErr
}

func extractTagFromLocation(loc string) string {
	const marker = "/releases/tag/"
	idx := strings.Index(loc, marker)
	if idx < 0 {
		return ""
	}
	rest := loc[idx+len(marker):]
	if q := strings.IndexAny(rest, "?#"); q >= 0 {
		rest = rest[:q]
	}
	rest = strings.Trim(rest, "/ \t\r\n")
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

func httpGetBytesWithProgress(ctx context.Context, client *http.Client, u string, onProgress func(downloaded, total int64)) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+CurrentVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}

	var dst bytes.Buffer
	if resp.ContentLength > 0 && resp.ContentLength <= maxUpgradeBinarySize {
		dst.Grow(int(resp.ContentLength))
	}

	lr := io.LimitReader(resp.Body, maxUpgradeBinarySize+1)
	buf := make([]byte, 32*1024)
	var downloaded int64
	var lastReported int64
	lastTick := time.Now()

	for {
		n, rerr := lr.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
			downloaded += int64(n)
			if downloaded > maxUpgradeBinarySize {
				return nil, fmt.Errorf("download %s exceeded %d bytes cap", u, maxUpgradeBinarySize)
			}
			if onProgress != nil && (downloaded-lastReported >= 512*1024 || time.Since(lastTick) >= 250*time.Millisecond) {
				onProgress(downloaded, resp.ContentLength)
				lastReported = downloaded
				lastTick = time.Now()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return nil, rerr
		}
	}
	if onProgress != nil && downloaded > 0 && downloaded != lastReported {
		onProgress(downloaded, resp.ContentLength)
	}
	return dst.Bytes(), nil
}

func parseChecksumForAsset(sumBytes []byte, assetName string) (string, error) {
	for _, ln := range strings.Split(string(sumBytes), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && strings.TrimPrefix(f[1], "./") == assetName {
			return strings.ToLower(strings.TrimSpace(f[0])), nil
		}
	}
	return "", fmt.Errorf("checksums.txt does not contain %s", assetName)
}

func defaultVerifyBinary(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("staged binary failed version check: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	banner := strings.TrimSpace(string(out))
	if banner == "" {
		return "", errors.New("staged binary returned empty version output")
	}
	return banner, nil
}

// InspectBackup returns metadata about the previous server binary (.bak) if present.
func InspectBackup(targetBinary string) (BackupInfo, bool) {
	if strings.TrimSpace(targetBinary) == "" {
		targetBinary = defaultTargetBinary
	}
	bak := targetBinary + ".bak"
	fi, err := os.Stat(bak)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return BackupInfo{}, false
	}
	info := BackupInfo{
		Path:    bak,
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
	}
	if banner, berr := defaultVerifyBinary(bak); berr == nil {
		info.Banner = banner
	}
	return info, true
}

func fileSHA256Hex(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func verifyRestartHealthy(restartFn func() error, activeFn func() bool, portProbeFn func(int) error, listenPort int) error {
	if err := restartFn(); err != nil {
		return err
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	var lastErr error
	for {
		if activeFn() {
			if listenPort > 0 && portProbeFn != nil {
				if perr := portProbeFn(listenPort); perr == nil {
					return nil
				} else {
					lastErr = perr
				}
			} else {
				return nil
			}
		} else {
			lastErr = errors.New("service not active yet")
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("service health check timed out after 2.5s")
	}
	return lastErr
}

// PerformOTAUpgrade downloads the target release binary, verifies its SHA-256 digest and
// runnable architecture, backs up the active binary, swaps atomically, restarts systemd,
// verifies active status + listen port health, and rolls back automatically on failure.
func (c *Controller) PerformOTAUpgrade(opts UpgradeOptions) (*UpgradeResult, error) {
	opts, listenPort := c.resolveUpgradeOptions(opts)

	if !opts.SkipLock && c.Tx != nil {
		unlock, err := c.Tx.acquireLock()
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	opts.ProgressFn(fmt.Sprintf("正在检查 %s 最新发行版 (当前: %s, 架构: %s)...", opts.Repo, CurrentVersion, opts.Arch))
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 25*time.Second)
	rel, err := CheckLatestRelease(checkCtx, opts)
	checkCancel()
	if err != nil {
		return nil, err
	}

	if !opts.Force && strings.EqualFold(normalizeVersionTag(rel.TagName), normalizeVersionTag(CurrentVersion)) {
		return &UpgradeResult{
			FromVersion:   CurrentVersion,
			ToVersion:     rel.TagName,
			AlreadyLatest: true,
			AssetName:     rel.AssetName,
		}, nil
	}

	target := opts.TargetBinary
	if !opts.SkipDiskCheck {
		if err := checkAvailableDiskSpace(filepath.Dir(target), minUpgradeDiskFreeByte); err != nil {
			return nil, err
		}
	}

	opts.ProgressFn(fmt.Sprintf("发现目标版本 %s，正在获取 checksums.txt 并校验发布清单...", rel.TagName))
	sumCtx, sumCancel := context.WithTimeout(context.Background(), 30*time.Second)
	sumBytes, err := httpGetBytesWithProgress(sumCtx, opts.HTTPClient, rel.ChecksumURL, nil)
	sumCancel()
	if err != nil {
		return nil, fmt.Errorf("获取校验清单失败: %w", err)
	}
	wantHash, err := parseChecksumForAsset(sumBytes, rel.AssetName)
	if err != nil {
		return nil, err
	}

	binCtx, binCancel := context.WithTimeout(context.Background(), 120*time.Second)
	binBytes, err := httpGetBytesWithProgress(binCtx, opts.HTTPClient, rel.BinaryURL, func(downloaded, total int64) {
		mbDone := float64(downloaded) / (1 << 20)
		if total > 0 {
			mbTot := float64(total) / (1 << 20)
			pct := float64(downloaded) * 100 / float64(total)
			opts.ProgressFn(fmt.Sprintf("正在下载 %s: %.1f / %.1f MB (%.0f%%)", rel.AssetName, mbDone, mbTot, pct))
		} else {
			opts.ProgressFn(fmt.Sprintf("正在下载 %s: %.1f MB", rel.AssetName, mbDone))
		}
	})
	binCancel()
	if err != nil {
		return nil, fmt.Errorf("下载服务端二进制失败: %w", err)
	}

	sum := sha256.Sum256(binBytes)
	gotHash := hex.EncodeToString(sum[:])
	if gotHash != wantHash {
		return nil, fmt.Errorf("SHA-256 校验失败 (expected=%s got=%s)，已终止替换", wantHash, gotHash)
	}
	opts.ProgressFn(fmt.Sprintf("SHA-256 校验通过 (%s...)", gotHash[:16]))

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, err
	}

	cfgDigestBefore := fileSHA256Hex(c.CfgPath)

	stagingPath := fmt.Sprintf("%s.staging.%d", target, os.Getpid())
	sf, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return nil, err
	}
	if _, err := sf.Write(binBytes); err != nil {
		_ = sf.Close()
		_ = os.Remove(stagingPath)
		return nil, err
	}
	_ = sf.Sync()
	if err := sf.Close(); err != nil {
		_ = os.Remove(stagingPath)
		return nil, err
	}
	defer os.Remove(stagingPath)

	banner, err := opts.VerifyBinFn(stagingPath)
	if err != nil {
		return nil, err
	}
	opts.ProgressFn("新版本可执行性自检通过: " + banner)

	var bakPath string
	if oldBytes, rerr := os.ReadFile(target); rerr == nil && len(oldBytes) > 0 {
		bakPath = target + ".bak"
		if berr := server.WriteFileAtomic(bakPath, oldBytes, 0o755); berr != nil {
			return nil, fmt.Errorf("备份旧版本失败: %w", berr)
		}
	}

	if err := os.Rename(stagingPath, target); err != nil {
		return nil, fmt.Errorf("替换可执行文件失败: %w", err)
	}

	if target == defaultTargetBinary {
		ensureLocalSymlink()
	}

	opts.ProgressFn("正在重启 Kestrel 服务端并执行启动与端口健康检查...")
	if startErr := verifyRestartHealthy(opts.RestartFn, opts.ActiveFn, opts.PortProbeFn, listenPort); startErr != nil {
		if bakPath != "" {
			if bakBytes, rerr := os.ReadFile(bakPath); rerr == nil {
				_ = server.WriteFileAtomic(target, bakBytes, 0o755)
			}
			_ = opts.RestartFn()
		}
		return nil, fmt.Errorf("升级后服务启动校验失败: %w (已自动回滚至 %s)", startErr, CurrentVersion)
	}

	if cfgDigestBefore != "" {
		if cfgDigestAfter := fileSHA256Hex(c.CfgPath); cfgDigestAfter != "" && cfgDigestAfter != cfgDigestBefore {
			opts.ProgressFn("警告: 检测到配置文件摘要在重启后发生外部变化，请确认配置状态。")
		}
	}

	if target == defaultTargetBinary {
		refreshSystemdUnitDescription(defaultSystemdUnit)
	}

	return &UpgradeResult{
		FromVersion:    CurrentVersion,
		ToVersion:      rel.TagName,
		AlreadyLatest:  false,
		AssetName:      rel.AssetName,
		SHA256:         gotHash,
		BackupPath:     bakPath,
		VerifiedBanner: banner,
	}, nil
}

// PerformOTARollback restores TargetBinary from its .bak snapshot, restarts systemd,
// verifies health, and reverts to pre-rollback if the backup fails to boot.
func (c *Controller) PerformOTARollback(opts UpgradeOptions) (*RollbackResult, error) {
	opts, listenPort := c.resolveUpgradeOptions(opts)

	if !opts.SkipLock && c.Tx != nil {
		unlock, err := c.Tx.acquireLock()
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	target := opts.TargetBinary
	bakPath := target + ".bak"
	bakBytes, err := os.ReadFile(bakPath)
	if err != nil || len(bakBytes) == 0 {
		return nil, fmt.Errorf("未找到可回滚的历史备份 (%s)", bakPath)
	}

	banner, err := opts.VerifyBinFn(bakPath)
	if err != nil {
		return nil, fmt.Errorf("历史备份校验失败 (%s): %w", bakPath, err)
	}
	opts.ProgressFn("备份校验通过，准备回滚至: " + banner)

	var prePath string
	if curBytes, rerr := os.ReadFile(target); rerr == nil && len(curBytes) > 0 {
		prePath = target + ".pre-rollback"
		if perr := server.WriteFileAtomic(prePath, curBytes, 0o755); perr != nil {
			return nil, fmt.Errorf("保存回滚前快照失败: %w", perr)
		}
	}

	if err := server.WriteFileAtomic(target, bakBytes, 0o755); err != nil {
		return nil, fmt.Errorf("恢复备份文件失败: %w", err)
	}

	opts.ProgressFn("正在重启 Kestrel 服务端并校验回滚后健康状态...")
	if startErr := verifyRestartHealthy(opts.RestartFn, opts.ActiveFn, opts.PortProbeFn, listenPort); startErr != nil {
		if prePath != "" {
			if preBytes, rerr := os.ReadFile(prePath); rerr == nil {
				_ = server.WriteFileAtomic(target, preBytes, 0o755)
			}
			_ = opts.RestartFn()
		}
		return nil, fmt.Errorf("回滚后服务启动失败: %w", startErr)
	}

	return &RollbackResult{
		FromVersion:     CurrentVersion,
		RestoredBanner:  banner,
		BackupPath:      bakPath,
		PreRollbackPath: prePath,
	}, nil
}

func ensureLocalSymlink() {
	if _, serr := os.Stat("/usr/local/bin"); serr != nil {
		return
	}
	for _, linkPath := range []string{"/usr/local/bin/ksl", "/usr/local/bin/gft"} {
		if dst, lerr := os.Readlink(linkPath); lerr != nil || dst != defaultTargetBinary {
			_ = os.Remove(linkPath)
			_ = os.Symlink(defaultTargetBinary, linkPath)
		}
	}
}

func refreshSystemdUnitDescription(unitPath string) {
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return
	}
	raw := string(b)
	if !strings.Contains(raw, "v3.2") && !strings.Contains(raw, "GhostFrame") {
		return
	}
	lines := strings.Split(raw, "\n")
	changed := false
	for i, ln := range lines {
		if strings.HasPrefix(ln, "Description=") {
			lines[i] = "Description=Kestrel-RTC (KRTC) v4.0 LTS Dual-Stack Server"
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := server.WriteFileAtomic(unitPath, []byte(strings.Join(lines, "\n")), 0o644); err == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
}
