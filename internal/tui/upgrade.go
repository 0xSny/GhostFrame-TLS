package tui

import (
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

// CurrentVersion is the canonical release identifier compiled into server & TUI binaries.
const CurrentVersion = "v4.0.0-LTS"

const (
	defaultGitHubAPIBase = "https://api.github.com"
	defaultGitHubWebBase = "https://github.com"
	defaultTargetBinary  = "/opt/ghostframe/gft-server"
	defaultSystemdUnit   = "/etc/systemd/system/ghostframe.service"
	maxUpgradeBinarySize = 128 << 20 // 128 MiB safety cap
)

// ReleaseInfo describes a resolved GitHub Release target and its verification assets.
type ReleaseInfo struct {
	TagName     string
	AssetName   string
	BinaryURL   string
	ChecksumURL string
	ViaRedirect bool
}

// UpgradeOptions parameterizes OTA self-upgrade and allows deterministic unit testing.
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
	VerifyBinFn   func(path string) (string, error)
	ProgressFn    func(msg string)
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
	s = strings.TrimPrefix(s, "gft-server ")
	return strings.TrimSpace(s)
}

func resolveReleaseOptions(opts UpgradeOptions) UpgradeOptions {
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
		opts.MirrorPrefix = strings.TrimSpace(os.Getenv("GFT_MIRROR"))
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
	opts = resolveReleaseOptions(opts)
	assetName := fmt.Sprintf("gft-server-linux-%s", opts.Arch)
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
	req.Header.Set("User-Agent", "GhostFrame-Updater/"+CurrentVersion)
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
		TagName string `json:"tag_name"`
		Assets  []struct {
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
		TagName:     strings.TrimSpace(payload.TagName),
		AssetName:   assetName,
		BinaryURL:   applyMirrorURL(mirror, binURL),
		ChecksumURL: applyMirrorURL(mirror, sumURL),
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
		req.Header.Set("User-Agent", "GhostFrame-Updater/"+CurrentVersion)
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

func httpGetBytesWithClient(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GhostFrame-Updater/"+CurrentVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpgradeBinarySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUpgradeBinarySize {
		return nil, fmt.Errorf("download %s exceeded %d bytes cap", u, maxUpgradeBinarySize)
	}
	return data, nil
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

// PerformOTAUpgrade downloads the target release binary, verifies its SHA-256 digest and
// runnable architecture, backs up the active binary, swaps atomically, restarts systemd,
// and rolls back automatically if startup health checks fail.
func (c *Controller) PerformOTAUpgrade(opts UpgradeOptions) (*UpgradeResult, error) {
	opts = resolveReleaseOptions(opts)
	if opts.RestartFn == nil {
		opts.RestartFn = c.Tx.RestartFn
	}
	if opts.ActiveFn == nil {
		opts.ActiveFn = c.Tx.ActiveFn
	}
	if opts.VerifyBinFn == nil {
		opts.VerifyBinFn = defaultVerifyBinary
	}
	if opts.ProgressFn == nil {
		opts.ProgressFn = func(msg string) {
			c.printf("%s\n", msg)
		}
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

	opts.ProgressFn(fmt.Sprintf("发现目标版本 %s，正在获取 checksums.txt 并下载 %s...", rel.TagName, rel.AssetName))
	sumCtx, sumCancel := context.WithTimeout(context.Background(), 30*time.Second)
	sumBytes, err := httpGetBytesWithClient(sumCtx, opts.HTTPClient, rel.ChecksumURL)
	sumCancel()
	if err != nil {
		return nil, fmt.Errorf("获取校验清单失败: %w", err)
	}
	wantHash, err := parseChecksumForAsset(sumBytes, rel.AssetName)
	if err != nil {
		return nil, err
	}

	binCtx, binCancel := context.WithTimeout(context.Background(), 120*time.Second)
	binBytes, err := httpGetBytesWithClient(binCtx, opts.HTTPClient, rel.BinaryURL)
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

	target := opts.TargetBinary
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, err
	}

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
	opts.ProgressFn("新版本自检通过: " + banner)

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
		if _, serr := os.Stat("/usr/local/bin"); serr == nil {
			linkPath := "/usr/local/bin/gft"
			if dst, lerr := os.Readlink(linkPath); lerr != nil || dst != defaultTargetBinary {
				_ = os.Remove(linkPath)
				_ = os.Symlink(defaultTargetBinary, linkPath)
			}
		}
	}

	opts.ProgressFn("正在重启 GhostFrame 服务端并执行启动健康检查...")
	var startErr error
	if err := opts.RestartFn(); err != nil {
		startErr = err
	} else {
		deadline := time.Now().Add(2500 * time.Millisecond)
		activeOK := false
		for {
			if opts.ActiveFn() {
				activeOK = true
				break
			}
			if !time.Now().Before(deadline) {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if !activeOK {
			startErr = errors.New("service failed to become active within 2.5s")
		}
	}

	if startErr != nil {
		if bakPath != "" {
			if bakBytes, rerr := os.ReadFile(bakPath); rerr == nil {
				_ = server.WriteFileAtomic(target, bakBytes, 0o755)
			}
			_ = opts.RestartFn()
		}
		return nil, fmt.Errorf("升级后服务启动校验失败: %w (已自动回滚至 %s)", startErr, CurrentVersion)
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

func refreshSystemdUnitDescription(unitPath string) {
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return
	}
	raw := string(b)
	if !strings.Contains(raw, "v3.2") {
		return
	}
	lines := strings.Split(raw, "\n")
	changed := false
	for i, ln := range lines {
		if strings.HasPrefix(ln, "Description=") && strings.Contains(ln, "v3.2") {
			lines[i] = "Description=GhostFrame-RTC (GFT) v4.0 LTS Dual-Stack Server"
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
