package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	defaultRepo         = "Spittingjiu/GhostFrame-TLS"
	defaultWorkflow     = "ios-dual-ipa.yml"
	defaultDistDir      = ".ios-dist"
	defaultListenAddr   = "0.0.0.0:18080"
	vpnArtifactName     = "GhostFrame-VPN-Unsigned-IPA"
	compArtifactName    = "GhostFrame-Companion-Unsigned-IPA"
	vpnIPAFileName      = "GhostFrame-VPN-Unsigned.ipa"
	compIPAFileName     = "GhostFrame-Companion-Unsigned.ipa"
	vpnIconFileName     = "icon-vpn.png"
	compIconFileName    = "icon-companion.png"
	maxArtifactZipBytes = 256 << 20
)

// RepoMetadata records the latest synchronized CI build details on disk.
type RepoMetadata struct {
	Repo          string `json:"repo"`
	Workflow      string `json:"workflow"`
	RunID         int64  `json:"run_id"`
	RunNumber     int64  `json:"run_number"`
	Version       string `json:"version"`
	SHA           string `json:"sha"`
	CommitTitle   string `json:"commit_title"`
	VersionDate   string `json:"version_date"`
	SyncedAt      string `json:"synced_at"`
	HTMLURL       string `json:"html_url"`
	VPNSize       int64  `json:"vpn_size"`
	CompanionSize int64  `json:"companion_size"`
}

// AppVersionEntry follows AltStore/SideStore version history schema.
type AppVersionEntry struct {
	Version              string `json:"version"`
	Date                 string `json:"date"`
	LocalizedDescription string `json:"localizedDescription"`
	DownloadURL          string `json:"downloadURL"`
	Size                 int64  `json:"size"`
}

// SourceApp combines ESign/OmniSign flat fields with AltStore versions[].
type SourceApp struct {
	Name                 string            `json:"name"`
	BundleIdentifier     string            `json:"bundleIdentifier"`
	DeveloperName        string            `json:"developerName"`
	Subtitle             string            `json:"subtitle"`
	LocalizedDescription string            `json:"localizedDescription"`
	IconURL              string            `json:"iconURL"`
	TintColor            string            `json:"tintColor"`
	Version              string            `json:"version"`
	VersionDate          string            `json:"versionDate"`
	VersionDescription   string            `json:"versionDescription"`
	DownloadURL          string            `json:"downloadURL"`
	Size                 int64             `json:"size"`
	Versions             []AppVersionEntry `json:"versions"`
}

// SourceManifest is the top-level OmniSign / ESign / AltStore source.json payload.
type SourceManifest struct {
	Name       string      `json:"name"`
	Identifier string      `json:"identifier"`
	Subtitle   string      `json:"subtitle"`
	SourceURL  string      `json:"sourceURL"`
	IconURL    string      `json:"iconURL"`
	Apps       []SourceApp `json:"apps"`
}

type ghWorkflowRunsResp struct {
	WorkflowRuns []ghRunItem `json:"workflow_runs"`
}

type ghRunItem struct {
	ID           int64  `json:"id"`
	RunNumber    int64  `json:"run_number"`
	HeadSHA      string `json:"head_sha"`
	DisplayTitle string `json:"display_title"`
	UpdatedAt    string `json:"updated_at"`
	CreatedAt    string `json:"created_at"`
	HTMLURL      string `json:"html_url"`
	HeadCommit   *struct {
		Message string `json:"message"`
	} `json:"head_commit"`
}

type ghCLIItem struct {
	DatabaseID   int64  `json:"databaseId"`
	Number       int64  `json:"number"`
	HeadSHA      string `json:"headSha"`
	DisplayTitle string `json:"displayTitle"`
	UpdatedAt    string `json:"updatedAt"`
	URL          string `json:"url"`
}

type ghArtifactsResp struct {
	Artifacts []struct {
		ID                 int64  `json:"id"`
		Name               string `json:"name"`
		SizeInBytes        int64  `json:"size_in_bytes"`
		ArchiveDownloadURL string `json:"archive_download_url"`
		Expired            bool   `json:"expired"`
	} `json:"artifacts"`
}

func main() {
	repo := flag.String("repo", defaultRepo, "GitHub repository (owner/name)")
	workflow := flag.String("workflow", defaultWorkflow, "GitHub Actions workflow filename")
	dir := flag.String("dir", defaultDistDir, "Local directory storing synced IPAs and source.json")
	listen := flag.String("listen", defaultListenAddr, "HTTP listen address")
	host := flag.String("host", "", "Override advertised LAN host IP (auto-detected if empty)")
	proxyFlag := flag.String("proxy", "", "Optional proxy URL (e.g. http://127.0.0.1:7891)")
	syncOnly := flag.Bool("sync", false, "Sync latest successful CI IPAs")
	serveOnly := flag.Bool("serve", false, "Start local OmniSign HTTP server")
	once := flag.Bool("once", false, "Sync once and exit without starting HTTP server")
	runID := flag.Int64("run-id", 0, "Optional specific GitHub Actions run ID to download")
	flag.Parse()

	doSync := *syncOnly
	doServe := *serveOnly
	if *once {
		doSync = true
		doServe = false
	} else if !*syncOnly && !*serveOnly {
		doSync = true
		doServe = true
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fatalf("resolve dir: %v", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		fatalf("create dir %s: %v", absDir, err)
	}

	lanHost := strings.TrimSpace(*host)
	if lanHost == "" {
		lanHost = detectLANIPv4()
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil || port == "" {
		port = "18080"
	}
	baseURL := fmt.Sprintf("http://%s:%s", lanHost, port)

	if err := ensureRepoIcons(absDir); err != nil {
		fatalf("generate icons: %v", err)
	}

	if doSync {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		meta, err := syncLatestArtifacts(ctx, *repo, *workflow, absDir, *proxyFlag, *runID)
		cancel()
		if err != nil {
			fatalf("sync artifacts failed: %v", err)
		}
		if err := writeStaticSourceFile(absDir, baseURL, meta); err != nil {
			fatalf("write source.json failed: %v", err)
		}
		fmt.Printf("[OK] Synced Build #%d (version=%s, sha=%s)\n", meta.RunNumber, meta.Version, shortSHA(meta.SHA))
		fmt.Printf("     VPN IPA       : %s (%.2f MB)\n", filepath.Join(absDir, vpnIPAFileName), float64(meta.VPNSize)/(1<<20))
		fmt.Printf("     Companion IPA : %s (%.2f MB)\n", filepath.Join(absDir, compIPAFileName), float64(meta.CompanionSize)/(1<<20))
		fmt.Printf("     OmniSign Source: %s/source.json\n", baseURL)
	}

	if doServe {
		if err := serveRepo(absDir, *listen, lanHost, port); err != nil {
			fatalf("server error: %v", err)
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
	os.Exit(1)
}

func isVirtualInterfaceName(name string) bool {
	n := strings.ToLower(name)
	for _, kw := range []string{
		"vmware", "vmnet", "vbox", "virtual", "wsl", "hyper-v",
		"vethernet", "docker", "tailscale", "utun", "clash", "mihomo",
		"zerotier", "loopback", "isatap", "teredo",
	} {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

func isPrivateRFC1918(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

// detectLANIPv4 detects the active physical LAN IPv4 address while ignoring VMware/virtual adapters.
func detectLANIPv4() string {
	type cand struct {
		ip   string
		prio int
	}
	nonVirtualIPs := make(map[string]string)
	virtualIPs := make(map[string]bool)
	var list []cand

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		isVirt := isVirtualInterfaceName(iface.Name)
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			s := ip4.String()
			if isVirt {
				virtualIPs[s] = true
				continue
			}
			nonVirtualIPs[s] = iface.Name
			prio := 4
			if ip4[0] == 192 && ip4[1] == 168 {
				prio = 1
			} else if ip4[0] == 10 {
				prio = 2
			} else if isPrivateRFC1918(ip4) {
				prio = 3
			}
			list = append(list, cand{ip: s, prio: prio})
		}
	}

	if conn, err := net.DialTimeout("udp4", "223.5.5.5:53", 500*time.Millisecond); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
			if ip4 := ua.IP.To4(); ip4 != nil && isPrivateRFC1918(ip4) && !virtualIPs[ip4.String()] {
				_ = conn.Close()
				return ip4.String()
			}
		}
		_ = conn.Close()
	}

	if len(list) > 0 {
		sort.SliceStable(list, func(i, j int) bool {
			return list[i].prio < list[j].prio
		})
		return list[0].ip
	}
	return "127.0.0.1"
}

func resolveProxyURL(explicit string) *url.URL {
	if s := strings.TrimSpace(explicit); s != "" {
		if u, err := url.Parse(s); err == nil {
			return u
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			if u, err := url.Parse(v); err == nil {
				return u
			}
		}
	}
	if tcpPortReachable("127.0.0.1:7891") {
		u, _ := url.Parse("http://127.0.0.1:7891")
		return u
	}
	if tcpPortReachable("127.0.0.1:7890") {
		if looksLikeSOCKS5("127.0.0.1:7890") {
			u, _ := url.Parse("socks5h://127.0.0.1:7890")
			return u
		}
		u, _ := url.Parse("http://127.0.0.1:7890")
		return u
	}
	return nil
}

func tcpPortReachable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func looksLikeSOCKS5(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return false
	}
	return resp[0] == 0x05
}

func buildHTTPClient(proxyURL *url.URL) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   3 * time.Minute,
		// Strip Authorization on cross-host redirects (required when GitHub redirects to Azure Blob Storage).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

func resolveGitBinary() string {
	if p, err := exec.LookPath("git"); err == nil {
		return p
	}
	candidates := []string{
		`C:\Program Files\Git\cmd\git.exe`,
		`C:\Program Files\Git\bin\git.exe`,
		`C:\Program Files (x86)\Git\cmd\git.exe`,
	}
	if localApp := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localApp != "" {
		candidates = append(candidates, filepath.Join(localApp, "Programs", "Git", "cmd", "git.exe"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return "git"
}

func resolveGitHubToken() string {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolveGitBinary(), "credential", "fill")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "[WARN] git credential fill failed: %v (%s)\n", err, strings.TrimSpace(string(ee.Stderr)))
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] git credential fill failed: %v\n", err)
		}
		return ""
	}
	for _, ln := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(ln, "password=") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "password="))
		}
	}
	return ""
}

func syncLatestArtifacts(ctx context.Context, repo, workflow, distDir, proxyOverride string, specificRunID int64) (*RepoMetadata, error) {
	proxyURL := resolveProxyURL(proxyOverride)

	if ghPath, err := exec.LookPath("gh"); err == nil {
		if tryErr := exec.CommandContext(ctx, ghPath, "auth", "status").Run(); tryErr == nil {
			fmt.Println("[SYNC] Using authenticated gh CLI...")
			if meta, gerr := syncViaGHCLI(ctx, ghPath, repo, workflow, distDir, proxyURL, specificRunID); gerr == nil {
				return meta, nil
			} else {
				fmt.Printf("[WARN] gh CLI sync failed (%v); falling back to native GitHub API...\n", gerr)
			}
		}
	}

	fmt.Println("[SYNC] Querying GitHub Actions API (native stdlib)...")
	return syncViaNativeAPI(ctx, repo, workflow, distDir, proxyURL, specificRunID)
}

func syncViaGHCLI(ctx context.Context, ghPath, repo, workflow, distDir string, proxyURL *url.URL, specificRunID int64) (*RepoMetadata, error) {
	env := os.Environ()
	if proxyURL != nil {
		p := proxyURL.String()
		env = append(env, "HTTPS_PROXY="+p, "HTTP_PROXY="+p)
	}

	var run ghCLIItem
	if specificRunID > 0 {
		cmd := exec.CommandContext(ctx, ghPath, "run", "view", fmt.Sprintf("%d", specificRunID), "--repo", repo,
			"--json", "databaseId,number,headSha,displayTitle,updatedAt,url")
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(out, &run); err != nil {
			return nil, err
		}
	} else {
		cmd := exec.CommandContext(ctx, ghPath, "run", "list", "--repo", repo, "--workflow", workflow,
			"--status", "success", "--limit", "1", "--json", "databaseId,number,headSha,displayTitle,updatedAt,url")
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		var list []ghCLIItem
		if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
			return nil, fmt.Errorf("no successful workflow runs found for %s", workflow)
		}
		run = list[0]
	}

	tmpDir, err := os.MkdirTemp(distDir, ".ghdl-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	dlCmd := exec.CommandContext(ctx, ghPath, "run", "download", fmt.Sprintf("%d", run.DatabaseID), "--repo", repo,
		"--dir", tmpDir, "-n", vpnArtifactName, "-n", compArtifactName)
	dlCmd.Env = env
	if out, err := dlCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gh run download: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	vpnSrc, err := findFirstIPA(filepath.Join(tmpDir, vpnArtifactName))
	if err != nil {
		return nil, err
	}
	compSrc, err := findFirstIPA(filepath.Join(tmpDir, compArtifactName))
	if err != nil {
		return nil, err
	}

	vpnSize, err := copyFileAtomic(vpnSrc, filepath.Join(distDir, vpnIPAFileName))
	if err != nil {
		return nil, err
	}
	compSize, err := copyFileAtomic(compSrc, filepath.Join(distDir, compIPAFileName))
	if err != nil {
		return nil, err
	}

	meta := buildMetadata(repo, workflow, run.DatabaseID, run.Number, run.HeadSHA, run.DisplayTitle, run.UpdatedAt, run.URL, vpnSize, compSize)
	if err := saveMetadata(distDir, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func syncViaNativeAPI(ctx context.Context, repo, workflow, distDir string, proxyURL *url.URL, specificRunID int64) (*RepoMetadata, error) {
	token := resolveGitHubToken()
	if token == "" {
		return nil, errors.New("GitHub token required to download workflow artifacts (set GH_TOKEN or sign in to git credential manager)")
	}
	client := buildHTTPClient(proxyURL)

	var run ghRunItem
	if specificRunID > 0 {
		u := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d", repo, specificRunID)
		if err := apiGetJSON(ctx, client, u, token, &run); err != nil {
			return nil, fmt.Errorf("fetch run %d: %w", specificRunID, err)
		}
	} else {
		u := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/%s/runs?status=success&per_page=1",
			repo, url.PathEscape(workflow))
		var resp ghWorkflowRunsResp
		if err := apiGetJSON(ctx, client, u, token, &resp); err != nil {
			return nil, fmt.Errorf("list workflow runs: %w", err)
		}
		if len(resp.WorkflowRuns) == 0 {
			return nil, fmt.Errorf("no successful runs found for workflow %s", workflow)
		}
		run = resp.WorkflowRuns[0]
	}

	artsURL := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/artifacts?per_page=30", repo, run.ID)
	var arts ghArtifactsResp
	if err := apiGetJSON(ctx, client, artsURL, token, &arts); err != nil {
		return nil, fmt.Errorf("list artifacts for run %d: %w", run.ID, err)
	}

	var vpnURL, compURL string
	for _, a := range arts.Artifacts {
		if a.Expired {
			continue
		}
		switch a.Name {
		case vpnArtifactName:
			vpnURL = a.ArchiveDownloadURL
		case compArtifactName:
			compURL = a.ArchiveDownloadURL
		}
	}
	if vpnURL == "" || compURL == "" {
		return nil, fmt.Errorf("run %d missing %s or %s", run.ID, vpnArtifactName, compArtifactName)
	}

	fmt.Printf("[SYNC] Downloading Build #%d (%s) artifacts...\n", run.RunNumber, shortSHA(run.HeadSHA))
	vpnZip, err := apiDownloadBytes(ctx, client, vpnURL, token)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", vpnArtifactName, err)
	}
	vpnSize, err := extractIPAFromZip(vpnZip, filepath.Join(distDir, vpnIPAFileName))
	if err != nil {
		return nil, fmt.Errorf("extract %s: %w", vpnIPAFileName, err)
	}

	compZip, err := apiDownloadBytes(ctx, client, compURL, token)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", compArtifactName, err)
	}
	compSize, err := extractIPAFromZip(compZip, filepath.Join(distDir, compIPAFileName))
	if err != nil {
		return nil, fmt.Errorf("extract %s: %w", compIPAFileName, err)
	}

	title := strings.TrimSpace(run.DisplayTitle)
	if title == "" && run.HeadCommit != nil {
		title = strings.TrimSpace(strings.Split(run.HeadCommit.Message, "\n")[0])
	}
	vDate := run.UpdatedAt
	if vDate == "" {
		vDate = run.CreatedAt
	}

	meta := buildMetadata(repo, workflow, run.ID, run.RunNumber, run.HeadSHA, title, vDate, run.HTMLURL, vpnSize, compSize)
	if err := saveMetadata(distDir, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func apiGetJSON(ctx context.Context, client *http.Client, u, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "GhostFrame-iOS-Repo-Sync/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

func apiDownloadBytes(ctx context.Context, client *http.Client, u, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "GhostFrame-iOS-Repo-Sync/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactZipBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArtifactZipBytes {
		return nil, fmt.Errorf("artifact archive exceeded %d bytes cap", maxArtifactZipBytes)
	}
	return data, nil
}

func extractIPAFromZip(zipData []byte, destPath string) (int64, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return 0, err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(f.Name))
		if strings.Contains(clean, "..") || !strings.HasSuffix(strings.ToLower(clean), ".ipa") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		n, werr := writeReaderAtomic(destPath, io.LimitReader(rc, maxArtifactZipBytes))
		_ = rc.Close()
		if werr != nil {
			return 0, werr
		}
		return n, nil
	}
	return 0, fmt.Errorf("no .ipa file found inside artifact archive")
}

func findFirstIPA(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".ipa") {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no .ipa found in %s", dir)
}

func copyFileAtomic(src, dst string) (int64, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return writeReaderAtomic(dst, f)
}

func writeReaderAtomic(dst string, r io.Reader) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", dst, os.Getpid())
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, r)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

func buildMetadata(repo, workflow string, runID, runNum int64, sha, title, vDate, htmlURL string, vpnSize, compSize int64) *RepoMetadata {
	if strings.TrimSpace(vDate) == "" {
		vDate = time.Now().UTC().Format(time.RFC3339)
	}
	return &RepoMetadata{
		Repo:          repo,
		Workflow:      workflow,
		RunID:         runID,
		RunNumber:     runNum,
		Version:       fmt.Sprintf("4.0.0.%d", runNum),
		SHA:           sha,
		CommitTitle:   title,
		VersionDate:   vDate,
		SyncedAt:      time.Now().UTC().Format(time.RFC3339),
		HTMLURL:       htmlURL,
		VPNSize:       vpnSize,
		CompanionSize: compSize,
	}
}

func saveMetadata(distDir string, meta *RepoMetadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = writeReaderAtomic(filepath.Join(distDir, "metadata.json"), bytes.NewReader(b))
	return err
}

func loadMetadata(distDir string) *RepoMetadata {
	meta := &RepoMetadata{
		Repo:        defaultRepo,
		Workflow:    defaultWorkflow,
		Version:     "4.0.0.1",
		VersionDate: time.Now().UTC().Format(time.RFC3339),
		CommitTitle: "GhostFrame-RTC iOS Build",
	}
	if b, err := os.ReadFile(filepath.Join(distDir, "metadata.json")); err == nil {
		_ = json.Unmarshal(b, meta)
	}
	if fi, err := os.Stat(filepath.Join(distDir, vpnIPAFileName)); err == nil {
		meta.VPNSize = fi.Size()
	}
	if fi, err := os.Stat(filepath.Join(distDir, compIPAFileName)); err == nil {
		meta.CompanionSize = fi.Size()
	}
	return meta
}

func buildSourceManifest(baseURL string, meta *RepoMetadata) SourceManifest {
	baseURL = strings.TrimRight(baseURL, "/")
	ver := meta.Version
	if ver == "" {
		ver = "4.0.0.1"
	}
	vDate := meta.VersionDate
	if vDate == "" {
		vDate = time.Now().UTC().Format(time.RFC3339)
	}
	short := shortSHA(meta.SHA)
	desc := fmt.Sprintf("Build #%d", meta.RunNumber)
	if short != "" {
		desc += " (" + short + ")"
	}
	if meta.CommitTitle != "" {
		desc += ": " + meta.CommitTitle
	}

	vpnURL := baseURL + "/" + vpnIPAFileName
	compURL := baseURL + "/" + compIPAFileName
	vpnIcon := baseURL + "/" + vpnIconFileName
	compIcon := baseURL + "/" + compIconFileName

	return SourceManifest{
		Name:       "GhostFrame-TLS iOS Repo",
		Identifier: "com.ghostframe.ios.repo",
		Subtitle:   fmt.Sprintf("Build #%d · GFT-RTC v4", meta.RunNumber),
		SourceURL:  baseURL + "/source.json",
		IconURL:    vpnIcon,
		Apps: []SourceApp{
			{
				Name:                 "GhostFrame VPN",
				BundleIdentifier:     "com.ghostframe.vpn",
				DeveloperName:        "GhostFrame Project",
				Subtitle:             "系统级 VPN + iOS 18 控制中心开关",
				LocalizedDescription: "GhostFrame-RTC 双栈 VPN 正式版（零 App Group，适配全能签重签与 iOS 18 控制中心开关 + 内置 RuleSet 分流）。",
				IconURL:              vpnIcon,
				TintColor:            "00D4FF",
				Version:              ver,
				VersionDate:          vDate,
				VersionDescription:   desc,
				DownloadURL:          vpnURL,
				Size:                 meta.VPNSize,
				Versions: []AppVersionEntry{{
					Version:              ver,
					Date:                 vDate,
					LocalizedDescription: desc,
					DownloadURL:          vpnURL,
					Size:                 meta.VPNSize,
				}},
			},
			{
				Name:                 "GhostFrame Companion",
				BundleIdentifier:     "com.ghostframe.companion",
				DeveloperName:        "GhostFrame Project",
				Subtitle:             "免 VPN 权限单进程本地代理伴侣版",
				LocalizedDescription: "单进程静音保活版（无需 NetworkExtension 权限，适配免费个人签/重签工具，内置 RuleSet 分流）。",
				IconURL:              compIcon,
				TintColor:            "10B981",
				Version:              ver,
				VersionDate:          vDate,
				VersionDescription:   desc,
				DownloadURL:          compURL,
				Size:                 meta.CompanionSize,
				Versions: []AppVersionEntry{{
					Version:              ver,
					Date:                 vDate,
					LocalizedDescription: desc,
					DownloadURL:          compURL,
					Size:                 meta.CompanionSize,
				}},
			},
		},
	}
}

func writeStaticSourceFile(distDir, baseURL string, meta *RepoMetadata) error {
	m := buildSourceManifest(baseURL, meta)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = writeReaderAtomic(filepath.Join(distDir, "source.json"), bytes.NewReader(b))
	return err
}

func ensureRepoIcons(distDir string) error {
	vpnDst := filepath.Join(distDir, vpnIconFileName)
	repoAppIcon := filepath.Join("ios", "Shared", "Assets.xcassets", "AppIcon.appiconset", "AppIcon-1024.png")
	if b, err := os.ReadFile(repoAppIcon); err == nil && len(b) > 0 {
		if werr := os.WriteFile(vpnDst, b, 0o644); werr != nil {
			return werr
		}
	} else if err := generateShieldIcon(vpnDst, color.RGBA{0x00, 0xD4, 0xFF, 0xFF}, color.RGBA{0x02, 0x84, 0xC7, 0xFF}); err != nil {
		return err
	}
	return generateShieldIcon(filepath.Join(distDir, compIconFileName), color.RGBA{0x10, 0xB9, 0x81, 0xFF}, color.RGBA{0x05, 0x96, 0x69, 0xFF})
}

func generateShieldIcon(dst string, topCol, botCol color.RGBA) error {
	const size = 180
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bgTop := color.RGBA{0x0A, 0x0E, 0x17, 0xFF}
	bgBot := color.RGBA{0x12, 0x1A, 0x2B, 0xFF}

	for y := 0; y < size; y++ {
		ty := float64(y) / float64(size-1)
		bg := lerpColor(bgTop, bgBot, ty)
		for x := 0; x < size; x++ {
			img.SetRGBA(x, y, bg)
			nx := (float64(x) - 90.0) / 56.0
			ny := (float64(y) - 86.0) / 62.0
			// Clean geometric shield silhouette centered at (90, 86)
			if ny >= -0.82 && ny <= 0.92 {
				halfW := 0.92
				if ny > 0.05 {
					t := (ny - 0.05) / 0.87
					halfW = 0.92 * (1.0 - t*t)
				}
				if math.Abs(nx) <= halfW {
					distEdge := math.Min(halfW-math.Abs(nx), math.Min(ny+0.82, 0.92-ny))
					c := lerpColor(topCol, botCol, (ny+0.82)/1.74)
					if distEdge > 0.14 && distEdge < 0.24 && ny > -0.58 && ny < 0.65 {
						c = color.RGBA{0xF0, 0xF9, 0xFF, 0xFF}
					}
					img.SetRGBA(x, y, c)
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	_, err := writeReaderAtomic(dst, &buf)
	return err
}

func lerpColor(a, b color.RGBA, t float64) color.RGBA {
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	return color.RGBA{
		R: uint8(float64(a.R) + (float64(b.R)-float64(a.R))*t),
		G: uint8(float64(a.G) + (float64(b.G)-float64(a.G))*t),
		B: uint8(float64(a.B) + (float64(b.B)-float64(a.B))*t),
		A: 0xFF,
	}
}

func shortSHA(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

var indexHTMLTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>GhostFrame iOS 软件源</title>
<style>
:root{color-scheme:dark;--bg:#090d16;--card:#111827;--bd:#1f2937;--cyan:#00d4ff;--green:#10b981;--txt:#f3f4f6;--muted:#9ca3af}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif;padding:20px 16px 40px;line-height:1.5}
.wrap{max-width:560px;margin:0 auto}
.hero{background:linear-gradient(145deg,#111827,#0c1424);border:1px solid #1e3a5f;border-radius:16px;padding:18px;margin-bottom:16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px}
h1{font-size:20px;font-weight:700;letter-spacing:.3px}
.badge{background:rgba(0,212,255,.15);color:var(--cyan);border:1px solid rgba(0,212,255,.4);border-radius:999px;padding:3px 10px;font-size:12px;font-weight:600;white-space:nowrap}
.meta{color:var(--muted);font-size:13px;word-break:break-word}
.urlbox{background:#070a11;border:1px solid var(--bd);border-radius:10px;padding:10px 12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;color:#7dd3fc;margin:12px 0;word-break:break-all}
.btn{display:block;width:100%;border:none;border-radius:12px;padding:13px 16px;font-size:15px;font-weight:600;text-align:center;text-decoration:none;cursor:pointer;transition:.15s}
.btn-primary{background:linear-gradient(90deg,#0284c7,#06b6d4);color:#fff}
.btn-green{background:rgba(16,185,129,.18);color:#34d399;border:1px solid rgba(16,185,129,.45)}
.btn-outline{background:#161f30;color:var(--txt);border:1px solid var(--bd)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:16px;margin-bottom:14px}
.app{display:flex;align-items:center;gap:14px;margin-bottom:12px}
.app img{width:54px;height:54px;border-radius:13px;border:1px solid #263449;flex-shrink:0}
.app h2{font-size:17px;font-weight:600}
.app p{font-size:13px;color:var(--muted)}
.size{font-size:12px;color:#60a5fa;font-family:ui-monospace,Menlo,monospace;margin-top:2px}
.tips{font-size:13px;color:var(--muted);padding-left:18px}
.tips li{margin:4px 0}
.toast{display:none;margin-top:10px;text-align:center;color:#34d399;font-size:13px;font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div class="top">
      <h1>GhostFrame-TLS iOS 源</h1>
      <span class="badge">{{.Version}} · #{{.RunNumber}}</span>
    </div>
    <div class="meta">Commit: {{.ShortSHA}} — {{.CommitTitle}}</div>
    <div class="urlbox" id="srcUrl">{{.SourceURL}}</div>
    <button class="btn btn-primary" onclick="copySrc()">一键复制全能签软件源地址</button>
    <div class="toast" id="toast">已复制到剪贴板，去全能签粘贴添加即可！</div>
  </div>

  <div class="card">
    <div class="app">
      <img src="/icon-vpn.png" alt="VPN">
      <div>
        <h2>GhostFrame VPN</h2>
        <p>系统级 VPN + iOS 18 控制中心开关（免 App Group）</p>
        <div class="size">{{.VPNSizeStr}}</div>
      </div>
    </div>
    <a class="btn btn-outline" href="/GhostFrame-VPN-Unsigned.ipa">直接下载 GhostFrame-VPN-Unsigned.ipa</a>
  </div>

  <div class="card">
    <div class="app">
      <img src="/icon-companion.png" alt="Companion">
      <div>
        <h2>GhostFrame Companion</h2>
        <p>免 VPN 权限单进程静音保活版（适合普通个人证书）</p>
        <div class="size">{{.CompSizeStr}}</div>
      </div>
    </div>
    <a class="btn btn-green" href="/GhostFrame-Companion-Unsigned.ipa">直接下载 GhostFrame-Companion-Unsigned.ipa</a>
  </div>

  <div class="card">
    <strong style="font-size:14px;display:block;margin-bottom:6px">全能签 / ESign 订阅方法</strong>
    <ol class="tips">
      <li>点击上方「一键复制全能签软件源地址」。</li>
      <li>打开 iPhone 全能签 -> 软件源 -> 右上角「+」粘贴订阅。</li>
      <li>之后每次云端新包同步完成，直接在全能签下拉刷新即可一键重签更新。</li>
    </ol>
  </div>
</div>
<script>
function copySrc(){
  var txt=document.getElementById('srcUrl').innerText.trim();
  function done(){var t=document.getElementById('toast');t.style.display='block';setTimeout(function(){t.style.display='none'},2600);}
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(txt).then(done).catch(fallback);
  }else{fallback();}
  function fallback(){
    var ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.focus();ta.select();
    try{document.execCommand('copy');done();}catch(e){prompt('请长按复制软件源地址:',txt);}
    document.body.removeChild(ta);
  }
}
</script>
</body>
</html>`))

func newRepoHandler(distDir, defaultHost, port string) http.Handler {
	mux := http.NewServeMux()

	resolveBaseURL := func(r *http.Request) string {
		h := strings.TrimSpace(r.Host)
		if h == "" {
			h = net.JoinHostPort(defaultHost, port)
		}
		return "http://" + h
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		meta := loadMetadata(distDir)
		base := resolveBaseURL(r)
		data := struct {
			Version     string
			RunNumber   int64
			ShortSHA    string
			CommitTitle string
			SourceURL   string
			VPNSizeStr  string
			CompSizeStr string
		}{
			Version:     meta.Version,
			RunNumber:   meta.RunNumber,
			ShortSHA:    shortSHA(meta.SHA),
			CommitTitle: meta.CommitTitle,
			SourceURL:   base + "/source.json",
			VPNSizeStr:  fmtBytesHuman(meta.VPNSize),
			CompSizeStr: fmtBytesHuman(meta.CompanionSize),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = indexHTMLTmpl.Execute(w, data)
	})

	mux.HandleFunc("/source.json", func(w http.ResponseWriter, r *http.Request) {
		meta := loadMetadata(distDir)
		manifest := buildSourceManifest(resolveBaseURL(r), meta)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(manifest)
	})

	serveStatic := func(path string, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, err := os.Stat(path); err != nil {
				http.NotFound(w, r)
				return
			}
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			http.ServeFile(w, r, path)
		}
	}

	mux.HandleFunc("/"+vpnIPAFileName, serveStatic(filepath.Join(distDir, vpnIPAFileName), "application/octet-stream"))
	mux.HandleFunc("/"+compIPAFileName, serveStatic(filepath.Join(distDir, compIPAFileName), "application/octet-stream"))
	mux.HandleFunc("/"+vpnIconFileName, serveStatic(filepath.Join(distDir, vpnIconFileName), "image/png"))
	mux.HandleFunc("/"+compIconFileName, serveStatic(filepath.Join(distDir, compIconFileName), "image/png"))

	return mux
}

func fmtBytesHuman(n int64) string {
	if n <= 0 {
		return "未同步 (.ipa 尚未拉取)"
	}
	return fmt.Sprintf("%.2f MB (%d bytes)", float64(n)/(1<<20), n)
}

func serveRepo(distDir, listenAddr, lanHost, port string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           newRepoHandler(distDir, lanHost, port),
		ReadHeaderTimeout: 10 * time.Second,
	}

	baseURL := fmt.Sprintf("http://%s:%s", lanHost, port)
	fmt.Printf("\n[SERVE] GhostFrame iOS OmniSign / ESign Source listening on %s\n", listenAddr)
	fmt.Printf("        软件源订阅 URL : %s/source.json\n", baseURL)
	fmt.Printf("        手机浏览器访问 : %s/\n", baseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
