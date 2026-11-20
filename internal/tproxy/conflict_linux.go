//go:build linux

package tproxy

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type knownProxyDef struct {
	ProcessNames []string
	InitService  string
	Label        string
}

var knownConflicts = []knownProxyDef{
	{ProcessNames: []string{"openaero-core", "sing-box"}, InitService: "openaero", Label: "OpenAero / sing-box"},
	{ProcessNames: []string{"clash", "mihomo"}, InitService: "openclash", Label: "OpenClash / Mihomo"},
	{ProcessNames: []string{"nikki"}, InitService: "nikki", Label: "Nikki"},
	{ProcessNames: []string{"homeproxy"}, InitService: "homeproxy", Label: "HomeProxy"},
	{ProcessNames: []string{"passwall", "xray", "v2ray"}, InitService: "passwall", Label: "PassWall"},
	{ProcessNames: []string{"passwall2"}, InitService: "passwall2", Label: "PassWall2"},
	{ProcessNames: []string{"ssr-redir", "ssr-local"}, InitService: "shadowsocksr", Label: "SSR Plus"},
}

// DetectConflicts inspects running proxy processes, non-fw4/non-ghost0 hijack rules/tables,
// and conflicting TUN interfaces so 0Ghost never enters a double-NAT or proxy loop.
func DetectConflicts() ConflictReport {
	var rep ConflictReport
	seenSvc := make(map[string]struct{})

	procs := scanProcNames()
	for _, def := range knownConflicts {
		for _, pname := range def.ProcessNames {
			if count, ok := procs[pname]; ok && count > 0 {
				if _, dup := seenSvc[def.InitService]; dup {
					continue
				}
				seenSvc[def.InitService] = struct{}{}
				rep.Items = append(rep.Items, ConflictItem{
					Kind:    "process",
					Name:    def.Label,
					Detail:  fmt.Sprintf("进程 %s 正在运行 (init=%s)", pname, def.InitService),
					Service: def.InitService,
				})
			}
		}
	}

	// Check non-standard TUN proxy interfaces (e.g. openaero0, Meta, clash).
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			low := strings.ToLower(ifc.Name)
			if ifc.Flags&net.FlagUp == 0 {
				continue
			}
			if low == "openaero0" || strings.Contains(low, "clash") || low == "meta" || strings.HasPrefix(low, "utun") || strings.HasPrefix(low, "singtun") {
				svc := ""
				if low == "openaero0" {
					svc = "openaero"
				}
				rep.Items = append(rep.Items, ConflictItem{
					Kind:    "route",
					Name:    "TUN 接口: " + ifc.Name,
					Detail:  "检测到活跃代理虚拟网卡 " + ifc.Name,
					Service: svc,
				})
			}
		}
	}

	// Check extra nftables tables beyond fw4 / ghost0.
	if out, err := exec.Command("nft", "list", "tables").Output(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || ln == "table inet fw4" || ln == "table inet ghost0" {
				continue
			}
			low := strings.ToLower(ln)
			if strings.Contains(low, "clash") || strings.Contains(low, "passwall") || strings.Contains(low, "sing") || strings.Contains(low, "aero") || strings.Contains(low, "homeproxy") || strings.Contains(low, "nikki") || strings.Contains(low, "ssr") {
				rep.Items = append(rep.Items, ConflictItem{
					Kind:   "firewall",
					Name:   ln,
					Detail: "检测到冲突防火墙表: " + ln,
				})
			}
		}
	}

	rep.HasConflict = len(rep.Items) > 0
	return rep
}

// ResolveConflicts safely stops detected third-party proxy init services and cleans stale rules.
func ResolveConflicts() ConflictReport {
	rep := DetectConflicts()
	if !rep.HasConflict {
		rep.Resolved = true
		return rep
	}

	stopped := make(map[string]struct{})
	for _, it := range rep.Items {
		svc := strings.TrimSpace(it.Service)
		if svc == "" {
			continue
		}
		if _, done := stopped[svc]; done {
			continue
		}
		initPath := filepath.Join("/etc/init.d", svc)
		if st, err := os.Stat(initPath); err == nil && !st.IsDir() {
			_ = exec.Command(initPath, "stop").Run()
			stopped[svc] = struct{}{}
			rep.Actions = append(rep.Actions, fmt.Sprintf("已安全停用冲突代理服务: %s", initPath))
		}
	}

	// Also clean leftover custom nftables proxy tables if any init script left them behind.
	if out, err := exec.Command("nft", "list", "tables").Output(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || ln == "table inet fw4" || ln == "table inet ghost0" {
				continue
			}
			low := strings.ToLower(ln)
			if strings.Contains(low, "clash") || strings.Contains(low, "passwall") || strings.Contains(low, "sing") || strings.Contains(low, "aero") || strings.Contains(low, "homeproxy") || strings.Contains(low, "nikki") || strings.Contains(low, "ssr") {
				parts := strings.Fields(ln)
				if len(parts) >= 3 && parts[0] == "table" {
					_ = exec.Command("nft", "delete", "table", parts[1], parts[2]).Run()
					rep.Actions = append(rep.Actions, "已清理残留防火墙表: "+ln)
				}
			}
		}
	}

	// Re-check after cleanup.
	after := DetectConflicts()
	after.Actions = rep.Actions
	after.Resolved = !after.HasConflict
	return after
}

func scanProcNames() map[string]int {
	res := make(map[string]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return res
	}
	myPID := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || pid == myPID {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err == nil {
			name := strings.TrimSpace(string(comm))
			if name != "" {
				res[name]++
			}
		}
		cmd, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && len(cmd) > 0 {
			arg0 := strings.Split(string(cmd), "\x00")[0]
			base := filepath.Base(strings.TrimSpace(arg0))
			if base != "" {
				res[base]++
			}
		}
	}
	return res
}
