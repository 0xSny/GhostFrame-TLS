// Command gen-rules fetches Loyalsoldier/clash-rules (and optional MetaCubeX sources),
// merges Kestrel curated direct/proxy/leak-check/DoH guard sets, guarantees strict
// zero-collision 64-bit domain suffix hash tables, and writes rules_bundle.zlib.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"ghostframe/internal/client"
)

func fetchLines(cli *http.Client, url string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-GenRules/1.0")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 32<<20))
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func parseRuleLine(raw string) (string, bool) {
	ln := strings.TrimSpace(raw)
	if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "payload:") {
		return "", false
	}
	ln = strings.TrimPrefix(ln, "- ")
	ln = strings.TrimSpace(ln)
	ln = strings.Trim(ln, "'\"")
	if strings.HasPrefix(ln, "regexp:") || strings.HasPrefix(ln, "keyword:") || strings.HasPrefix(ln, "ip-cidr") {
		return "", false
	}
	if idx := strings.Index(ln, ":"); idx >= 0 {
		prefix := strings.ToLower(strings.TrimSpace(ln[:idx]))
		if prefix == "domain" || prefix == "domain-suffix" || prefix == "full" {
			ln = ln[idx+1:]
		}
	}
	if strings.Contains(ln, ",") {
		parts := strings.Split(ln, ",")
		if len(parts) >= 2 {
			ln = parts[1]
		}
	}
	ln = strings.TrimSpace(strings.ToLower(ln))
	ln = strings.TrimPrefix(ln, "+.")
	ln = strings.TrimPrefix(ln, ".")
	ln = strings.TrimSuffix(ln, ".")
	if ln == "" || !strings.Contains(ln, ".") || strings.ContainsAny(ln, " */") {
		return "", false
	}
	return ln, true
}

func main() {
	outPath := flag.String("out", "internal/client/rules_bundle.zlib", "output path for compressed KSLR rule bundle")
	directURL := flag.String("direct-url", "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt", "direct domain list URL")
	proxyURL := flag.String("proxy-url", "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt", "proxy domain list URL")
	gfwURL := flag.String("gfw-url", "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt", "GFW domain list URL")
	flag.Parse()

	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	cli := &http.Client{Transport: tr, Timeout: 45 * time.Second}

	proxySet := make(map[string]struct{}, 32000)
	directSet := make(map[string]struct{}, 120000)

	addDomains := func(dst map[string]struct{}, url string) int {
		lines, err := fetchLines(cli, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetch %s failed: %v\n", url, err)
			os.Exit(1)
		}
		n := 0
		for _, ln := range lines {
			if d, ok := parseRuleLine(ln); ok {
				if _, exists := dst[d]; !exists {
					dst[d] = struct{}{}
					n++
				}
			}
		}
		return n
	}

	nProxy := addDomains(proxySet, *proxyURL)
	nGFW := addDomains(proxySet, *gfwURL)
	nDirect := addDomains(directSet, *directURL)

	// Merge curated Kestrel sets and mini-game SDKs.
	for _, d := range client.BuiltinProxyDomains() {
		proxySet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	for _, d := range client.LeakAndDoHGuardDomains() {
		proxySet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	extraCN := []string{
		"cocos.com", "egret.com", "layaair.com", "tapdb.net", "thinkingdata.cn",
		"umeng.com", "umengcloud.com", "getui.com", "jpush.cn", "leancloud.cn",
		"bmob.cn", "qbox.me", "clouddn.com", "qnssl.com", "aixifan.com", "acfun.cn",
	}
	for _, d := range client.BuiltinDirectDomains() {
		directSet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	for _, d := range extraCN {
		directSet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}

	// Curated BuiltinDirectDomains win over community proxy lists so CN CDNs (steamcontent, cdn-apple, windowsupdate, kimi.ai) stay direct.
	curatedDirect := make(map[string]struct{})
	for _, d := range client.BuiltinDirectDomains() {
		d = strings.ToLower(strings.TrimSpace(d))
		curatedDirect[d] = struct{}{}
		delete(proxySet, d)
	}

	// Leak-check & DoH guard domains and all Proxy domains MUST NEVER remain in Direct.
	for _, d := range client.LeakAndDoHGuardDomains() {
		d = strings.ToLower(strings.TrimSpace(d))
		delete(directSet, d)
		proxySet[d] = struct{}{}
	}
	for d := range proxySet {
		if _, keepCurated := curatedDirect[d]; !keepCurated {
			delete(directSet, d)
		}
	}

	proxySlice := make([]string, 0, len(proxySet))
	for d := range proxySet {
		proxySlice = append(proxySlice, d)
	}
	directSlice := make([]string, 0, len(directSet))
	for d := range directSet {
		directSlice = append(directSlice, d)
	}

	blob, salt, pn, dn, err := client.EncodeCompactRuleBundle(proxySlice, directSlice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode bundle failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s failed: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s: fetched(proxy=%d gfw=%d direct=%d) -> packed(proxy=%d direct=%d total=%d) salt=%d size=%d bytes (~%.2f MiB RAM index)\n",
		*outPath, nProxy, nGFW, nDirect, pn, dn, pn+dn, salt, len(blob), float64((pn+dn)*8)/(1024*1024))
}
