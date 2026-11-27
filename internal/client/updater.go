package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultClientReleaseRepo hosts pure-binary releases (redirected to 0xSny/Ghost on GitHub).
	DefaultClientReleaseRepo = "Spittingjiu/Ghost"
	ClientWindowsAssetName   = "Kestrel-Pro-windows-amd64.exe"
	defaultGitHubAPIBase     = "https://api.github.com"
	defaultGitHubWebBase     = "https://github.com"
	maxClientBinaryBytes     = 64 << 20 // 64 MiB safety cap
)

// ClientReleaseInfo describes an available Kestrel Pro release on GitHub.
type ClientReleaseInfo struct {
	TagName      string `json:"tag_name"`
	Current      string `json:"current_version"`
	HasUpdate    bool   `json:"has_update"`
	AssetName    string `json:"asset_name"`
	AssetSize    int64  `json:"asset_size"`
	BinaryURL    string `json:"binary_url"`
	ChecksumURL  string `json:"checksum_url"`
	ReleaseURL   string `json:"release_url"`
	PublishedAt  string `json:"published_at,omitempty"`
	ReleaseNotes string `json:"release_notes,omitempty"`
	ViaTunnel    bool   `json:"via_tunnel,omitempty"`
}

// UpdateCheckOptions configures GitHub release lookup for tests and mirrors.
type UpdateCheckOptions struct {
	Repo           string
	AssetName      string
	CurrentVersion string
	MirrorPrefix   string
	APIBaseURL     string
	WebBaseURL     string
	HTTPClient     *http.Client
}

type githubReleasePayload struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	Body        string `json:"body"`
	Assets      []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func resolveClientUpdateOpts(opts UpdateCheckOptions) UpdateCheckOptions {
	if strings.TrimSpace(opts.Repo) == "" {
		opts.Repo = DefaultClientReleaseRepo
	}
	if strings.TrimSpace(opts.AssetName) == "" {
		opts.AssetName = ClientWindowsAssetName
	}
	if strings.TrimSpace(opts.CurrentVersion) == "" {
		opts.CurrentVersion = Version
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
	return opts
}

func applyMirrorURL(mirrorPrefix, target string) string {
	mp := strings.TrimSpace(mirrorPrefix)
	if mp == "" {
		return target
	}
	return strings.TrimRight(mp, "/") + "/" + strings.TrimLeft(target, "/")
}

type semverTuple struct {
	nums [3]int
	pre  string
}

func parseSemver(raw string) (semverTuple, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if s == "" {
		return semverTuple{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semverTuple{}, false
	}
	var out semverTuple
	out.pre = pre
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return semverTuple{}, false
		}
		out.nums[i] = v
	}
	return out, true
}

// CompareVersions compares two semantic version strings (e.g. "v4.2.6" vs "4.2.5").
// Returns 1 if a > b, -1 if a < b, 0 if equal.
func CompareVersions(a, b string) int {
	sa, okA := parseSemver(a)
	sb, okB := parseSemver(b)
	if okA && okB {
		for i := 0; i < 3; i++ {
			if sa.nums[i] > sb.nums[i] {
				return 1
			}
			if sa.nums[i] < sb.nums[i] {
				return -1
			}
		}
		if sa.pre == "" && sb.pre != "" {
			return 1
		}
		if sa.pre != "" && sb.pre == "" {
			return -1
		}
		return strings.Compare(sa.pre, sb.pre)
	}
	na := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(a), "v"), "V")
	nb := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(b), "v"), "V")
	if na == nb {
		return 0
	}
	if na > nb {
		return 1
	}
	return -1
}

func payloadToReleaseInfo(p githubReleasePayload, opts UpdateCheckOptions) (*ClientReleaseInfo, bool) {
	if p.Draft || p.Prerelease || strings.TrimSpace(p.TagName) == "" {
		return nil, false
	}
	var binURL, sumURL string
	var binSize int64
	for _, a := range p.Assets {
		switch a.Name {
		case opts.AssetName:
			binURL = a.URL
			binSize = a.Size
		case "checksums.txt":
			sumURL = a.URL
		}
	}
	if binURL == "" || sumURL == "" {
		return nil, false
	}
	tag := strings.TrimSpace(p.TagName)
	relURL := strings.TrimSpace(p.HTMLURL)
	if relURL == "" {
		relURL = fmt.Sprintf("%s/%s/releases/tag/%s", opts.WebBaseURL, opts.Repo, tag)
	}
	notes := summarizeUpdateNotes(p.Body)
	return &ClientReleaseInfo{
		TagName:      tag,
		Current:      opts.CurrentVersion,
		HasUpdate:    CompareVersions(tag, opts.CurrentVersion) > 0,
		AssetName:    opts.AssetName,
		AssetSize:    binSize,
		BinaryURL:    applyMirrorURL(opts.MirrorPrefix, binURL),
		ChecksumURL:  applyMirrorURL(opts.MirrorPrefix, sumURL),
		ReleaseURL:   relURL,
		PublishedAt:  strings.TrimSpace(p.PublishedAt),
		ReleaseNotes: notes,
	}, true
}

func summarizeUpdateNotes(body string) string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		lines = append(lines, ln)
		if len(lines) >= 6 {
			break
		}
	}
	s := strings.Join(lines, "\n")
	if len(s) > 420 {
		s = s[:417] + "..."
	}
	return s
}

func (e *Engine) makeHTTPClientsForRemote(opts UpdateCheckOptions, timeout time.Duration) (clients []*http.Client, cleanup func()) {
	if opts.HTTPClient != nil {
		return []*http.Client{opts.HTTPClient}, func() {}
	}
	var transports []*http.Transport
	if e != nil && e.IsConnected() {
		trTunnel := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				st, err := e.TunnelStream(addr)
				if err != nil {
					return nil, err
				}
				return dataStreamNetConn{DataStream: st}, nil
			},
		}
		transports = append(transports, trTunnel)
		clients = append(clients, &http.Client{Transport: trTunnel, Timeout: timeout})
	}
	trDirect := &http.Transport{DisableKeepAlives: true}
	if e != nil {
		trDirect.DialContext = e.DirectDialContext
	}
	transports = append(transports, trDirect)
	clients = append(clients, &http.Client{Transport: trDirect, Timeout: timeout})

	return clients, func() {
		for _, tr := range transports {
			tr.CloseIdleConnections()
		}
	}
}

// CheckClientUpdate queries GitHub Releases (tunnel-first when connected, direct fallback)
// and resolves the highest available release carrying Kestrel-Pro-windows-amd64.exe + checksums.txt.
func (e *Engine) CheckClientUpdate(ctx context.Context, opts UpdateCheckOptions) (*ClientReleaseInfo, error) {
	opts = resolveClientUpdateOpts(opts)
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
	}

	clients, cleanup := e.makeHTTPClientsForRemote(opts, 18*time.Second)
	defer cleanup()

	var lastErr error
	for idx, hc := range clients {
		viaTunnel := opts.HTTPClient == nil && e != nil && e.IsConnected() && idx == 0
		info, err := checkReleaseWithHTTPClient(ctx, hc, opts)
		if err == nil {
			info.ViaTunnel = viaTunnel
			return info, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func checkReleaseWithHTTPClient(ctx context.Context, hc *http.Client, opts UpdateCheckOptions) (*ClientReleaseInfo, error) {
	listURL := fmt.Sprintf("%s/repos/%s/releases?per_page=8", opts.APIBaseURL, opts.Repo)
	info, listErr := fetchBestReleaseFromList(ctx, hc, listURL, opts)
	if listErr == nil {
		return info, nil
	}

	latestAPIURL := fmt.Sprintf("%s/repos/%s/releases/latest", opts.APIBaseURL, opts.Repo)
	info, apiErr := fetchSingleReleaseFromAPI(ctx, hc, latestAPIURL, opts)
	if apiErr == nil {
		return info, nil
	}

	rawLatestURL := fmt.Sprintf("%s/%s/releases/latest", opts.WebBaseURL, opts.Repo)
	info, redirErr := fetchReleaseFromLatestRedirect(ctx, hc, rawLatestURL, opts)
	if redirErr == nil {
		return info, nil
	}
	return nil, fmt.Errorf("检查更新失败 (list: %v; latest: %v; redirect: %v)", listErr, apiErr, redirErr)
}

func fetchBestReleaseFromList(ctx context.Context, hc *http.Client, apiURL string, opts UpdateCheckOptions) (*ClientReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+opts.CurrentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var list []githubReleasePayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return nil, err
	}
	var best *ClientReleaseInfo
	for _, item := range list {
		cand, ok := payloadToReleaseInfo(item, opts)
		if !ok {
			continue
		}
		if best == nil || CompareVersions(cand.TagName, best.TagName) > 0 {
			best = cand
		}
	}
	if best == nil {
		return nil, fmt.Errorf("未找到包含 %s 的有效发布", opts.AssetName)
	}
	return best, nil
}

func fetchSingleReleaseFromAPI(ctx context.Context, hc *http.Client, apiURL string, opts UpdateCheckOptions) (*ClientReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+opts.CurrentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var p githubReleasePayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&p); err != nil {
		return nil, err
	}
	info, ok := payloadToReleaseInfo(p, opts)
	if !ok {
		return nil, fmt.Errorf("release %s missing %s or checksums.txt", p.TagName, opts.AssetName)
	}
	return info, nil
}

func fetchReleaseFromLatestRedirect(ctx context.Context, baseClient *http.Client, rawLatestURL string, opts UpdateCheckOptions) (*ClientReleaseInfo, error) {
	noFollow := *baseClient
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	candidates := []string{rawLatestURL}
	if strings.TrimSpace(opts.MirrorPrefix) != "" {
		candidates = []string{applyMirrorURL(opts.MirrorPrefix, rawLatestURL), rawLatestURL}
	}
	var lastErr error
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Kestrel-Updater/"+opts.CurrentVersion)
		resp, err := noFollow.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		loc := resp.Header.Get("Location")
		tag := extractReleaseTag(loc)
		if tag == "" && resp.Request != nil && resp.Request.URL != nil {
			tag = extractReleaseTag(resp.Request.URL.String())
		}
		if tag != "" {
			baseDL := fmt.Sprintf("%s/%s/releases/download/%s", opts.WebBaseURL, opts.Repo, tag)
			return &ClientReleaseInfo{
				TagName:     tag,
				Current:     opts.CurrentVersion,
				HasUpdate:   CompareVersions(tag, opts.CurrentVersion) > 0,
				AssetName:   opts.AssetName,
				BinaryURL:   applyMirrorURL(opts.MirrorPrefix, baseDL+"/"+opts.AssetName),
				ChecksumURL: applyMirrorURL(opts.MirrorPrefix, baseDL+"/checksums.txt"),
				ReleaseURL:  fmt.Sprintf("%s/%s/releases/tag/%s", opts.WebBaseURL, opts.Repo, tag),
			}, nil
		}
		lastErr = fmt.Errorf("unexpected redirect HTTP %d", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = errors.New("redirect failed")
	}
	return nil, lastErr
}

func extractReleaseTag(raw string) string {
	idx := strings.LastIndex(raw, "/releases/tag/")
	if idx < 0 {
		return ""
	}
	tag := raw[idx+len("/releases/tag/"):]
	if q := strings.IndexAny(tag, "?#/"); q >= 0 {
		tag = tag[:q]
	}
	return strings.TrimSpace(tag)
}

// ParseChecksumForAsset extracts the hex SHA-256 checksum for assetName from checksums.txt content.
func ParseChecksumForAsset(checksumsText, assetName string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(checksumsText))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		hashHex := strings.ToLower(strings.TrimSpace(fields[0]))
		name := strings.TrimPrefix(strings.TrimSpace(fields[len(fields)-1]), "*")
		if name == assetName && len(hashHex) == 64 {
			if _, err := hex.DecodeString(hashHex); err == nil {
				return hashHex, nil
			}
		}
	}
	return "", fmt.Errorf("checksums.txt 未包含 %s 的 SHA-256 校验值", assetName)
}

// DownloadAndVerifyClientUpdate downloads checksums.txt + the release binary (via tunnel first when
// connected, or direct fallback), verifies SHA-256 and Windows PE magic, and writes cleanly to destPath.
func (e *Engine) DownloadAndVerifyClientUpdate(
	ctx context.Context,
	info *ClientReleaseInfo,
	destPath string,
	opts UpdateCheckOptions,
	onProgress func(downloaded, total int64),
) error {
	if info == nil || info.BinaryURL == "" || info.ChecksumURL == "" {
		return errors.New("缺少更新下载地址或校验信息")
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
	}

	opts = resolveClientUpdateOpts(opts)
	clients, cleanup := e.makeHTTPClientsForRemote(opts, 3*time.Minute)
	defer cleanup()

	var lastErr error
	for _, hc := range clients {
		sumText, err := downloadSmallText(ctx, hc, info.ChecksumURL, opts.CurrentVersion)
		if err != nil {
			lastErr = fmt.Errorf("下载校验文件失败: %w", err)
			continue
		}
		wantSHA, err := ParseChecksumForAsset(sumText, info.AssetName)
		if err != nil {
			return err
		}
		if err := downloadVerifiedBinary(ctx, hc, info.BinaryURL, destPath, wantSHA, info.AssetSize, opts.CurrentVersion, onProgress); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func downloadSmallText(ctx context.Context, hc *http.Client, rawURL, ver string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+ver)
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func downloadVerifiedBinary(
	ctx context.Context,
	hc *http.Client,
	rawURL string,
	destPath string,
	wantSHA string,
	hintSize int64,
	ver string,
	onProgress func(downloaded, total int64),
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Kestrel-Updater/"+ver)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("下载新版程序失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	if total <= 0 {
		total = hintSize
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	tmp := destPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}

	h := sha256.New()
	buf := make([]byte, 32*1024)
	var written int64
	var head [2]byte
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if written == 0 && n >= 2 {
				head[0], head[1] = buf[0], buf[1]
			} else if written == 1 && n >= 1 {
				head[1] = buf[0]
			}
			written += int64(n)
			if written > maxClientBinaryBytes {
				_ = f.Close()
				_ = os.Remove(tmp)
				return fmt.Errorf("安装包体积异常 (>%d MB)", maxClientBinaryBytes>>20)
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				_ = f.Close()
				_ = os.Remove(tmp)
				return werr
			}
			_, _ = h.Write(buf[:n])
			if onProgress != nil {
				onProgress(written, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return rerr
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if written < 1024*1024 || head[0] != 'M' || head[1] != 'Z' {
		_ = os.Remove(tmp)
		return errors.New("下载文件不是有效的 Windows 可执行文件")
	}
	gotSHA := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotSHA, wantSHA) {
		_ = os.Remove(tmp)
		return fmt.Errorf("SHA-256 校验不匹配 (got=%s want=%s)", gotSHA[:12], wantSHA[:12])
	}
	_ = os.Remove(destPath)
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
