package client

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
)

// RouteMode controls client split-tunneling behavior.
type RouteMode string

const (
	RouteRule   RouteMode = "rule"   // Mainland CN / Private direct + auto system proxy
	RouteGlobal RouteMode = "global" // All traffic (except loopback) via GhostFrame + auto system proxy
	RouteCore   RouteMode = "core"   // Port-only mode (10808/10809 via tunnel, never touches system proxy)
	RouteDirect RouteMode = "direct" // Legacy config alias automatically mapped to RouteCore
)

// RouteAction is the per-request forwarding decision.
type RouteAction int

const (
	ActionProxy RouteAction = iota
	ActionDirect
)

func (a RouteAction) String() string {
	if a == ActionDirect {
		return "direct"
	}
	return "proxy"
}

type ipRange struct {
	lo uint32
	hi uint32
}

// Router classifies destinations without triggering local DNS lookups for domains.
type Router struct {
	cnRanges []ipRange
}

// NewRouter constructs a Router preloaded with private and Mainland China IPv4 ranges.
func NewRouter() *Router {
	cidrs := []string{
		// Private / Loopback / Link-Local / CGNAT
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// Major Mainland China IPv4 allocations (ChinaNet / CMCC / Unicom / Ali / Tencent / Baidu / CERNET / Public DNS)
		"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
		"1.1.0.0/24", "1.1.2.0/23", "1.1.4.0/22", "1.1.8.0/21",
		"1.2.0.0/23", "1.2.4.0/22", "1.2.8.0/21",
		"1.4.0.0/22", "1.4.4.0/23", "1.4.8.0/21",
		"1.8.0.0/16", "1.12.0.0/14", "1.24.0.0/13", "1.48.0.0/15", "1.50.0.0/16",
		"1.56.0.0/13", "1.68.0.0/14", "1.80.0.0/13", "1.180.0.0/14", "1.184.0.0/13", "1.192.0.0/13",
		"14.0.12.0/22", "14.16.0.0/12", "14.96.0.0/11", "14.128.0.0/12", "14.144.0.0/12", "14.192.0.0/11",
		"27.0.128.0/22", "27.8.0.0/13", "27.16.0.0/12", "27.36.0.0/14", "27.40.0.0/13", "27.50.128.0/17",
		"27.54.192.0/18", "27.98.208.0/20", "27.112.0.0/15", "27.128.0.0/12", "27.148.0.0/14", "27.152.0.0/13", "27.184.0.0/13", "27.192.0.0/11",
		"36.0.0.0/13", "36.16.0.0/12", "36.32.0.0/12", "36.48.0.0/12", "36.96.0.0/11", "36.128.0.0/10", "36.192.0.0/12",
		"39.64.0.0/11", "39.96.0.0/12", "39.128.0.0/10",
		"42.0.128.0/17", "42.4.0.0/14", "42.48.0.0/13", "42.80.0.0/12", "42.96.0.0/14", "42.120.0.0/14", "42.128.0.0/12", "42.176.0.0/12", "42.192.0.0/13", "42.200.0.0/14", "42.224.0.0/12", "42.240.0.0/12",
		"47.92.0.0/14", "47.96.0.0/12", "47.112.0.0/13",
		"49.4.0.0/15", "49.51.0.0/16", "49.64.0.0/11", "49.112.0.0/13", "49.140.0.0/14", "49.220.0.0/14", "49.232.0.0/14",
		"58.16.0.0/12", "58.32.0.0/11", "58.64.0.0/12", "58.82.0.0/15", "58.99.128.0/17", "58.100.0.0/14", "58.128.0.0/12", "58.192.0.0/12", "58.208.0.0/12", "58.240.0.0/12",
		"59.32.0.0/11", "59.64.0.0/12", "59.80.0.0/14", "59.108.0.0/14", "59.110.0.0/15", "59.151.0.0/16", "59.172.0.0/14", "59.192.0.0/10",
		"60.0.0.0/12", "60.16.0.0/13", "60.24.0.0/14", "60.28.0.0/15", "60.48.0.0/12", "60.160.0.0/11", "60.194.0.0/15", "60.200.0.0/13", "60.208.0.0/12", "60.224.0.0/12", "60.247.0.0/16", "60.255.0.0/16",
		"61.48.0.0/13", "61.128.0.0/10", "61.232.0.0/14", "61.236.0.0/15", "61.240.0.0/13",
		"101.0.0.0/15", "101.4.0.0/14", "101.16.0.0/12", "101.32.0.0/12", "101.64.0.0/10", "101.128.0.0/12", "101.192.0.0/12", "101.224.0.0/12", "101.240.0.0/13",
		"106.0.0.0/10", "106.64.0.0/12", "106.80.0.0/12", "106.112.0.0/13", "106.120.0.0/14", "106.224.0.0/12",
		"110.0.0.0/12", "110.16.0.0/13", "110.40.0.0/14", "110.52.0.0/14", "110.72.0.0/12", "110.80.0.0/12", "110.96.0.0/12", "110.152.0.0/13", "110.166.0.0/15", "110.176.0.0/12", "110.192.0.0/11", "110.240.0.0/12",
		"111.0.0.0/10", "111.112.0.0/12", "111.128.0.0/10", "111.192.0.0/11", "111.224.0.0/12",
		"112.0.0.0/10", "112.64.0.0/11", "112.96.0.0/12", "112.112.0.0/13", "112.120.0.0/14", "112.124.0.0/14", "112.192.0.0/12", "112.224.0.0/11",
		"113.0.0.0/11", "113.44.0.0/14", "113.56.0.0/13", "113.64.0.0/10", "113.128.0.0/12", "113.144.0.0/12", "113.192.0.0/11", "113.224.0.0/12", "113.240.0.0/12",
		"114.16.0.0/12", "114.32.0.0/11", "114.64.0.0/11", "114.96.0.0/11", "114.112.0.0/14", "114.128.0.0/12", "114.212.0.0/14", "114.216.0.0/13", "114.224.0.0/11",
		"115.16.0.0/12", "115.32.0.0/11", "115.84.0.0/14", "115.148.0.0/14", "115.152.0.0/13", "115.168.0.0/13", "115.192.0.0/11", "115.224.0.0/12",
		"116.0.0.0/12", "116.16.0.0/12", "116.52.0.0/14", "116.64.0.0/12", "116.112.0.0/12", "116.128.0.0/11", "116.160.0.0/12", "116.176.0.0/12", "116.192.0.0/11", "116.224.0.0/11",
		"117.0.0.0/11", "117.32.0.0/11", "117.64.0.0/11", "117.96.0.0/12", "117.112.0.0/12", "117.128.0.0/10",
		"118.16.0.0/12", "118.64.0.0/11", "118.112.0.0/12", "118.128.0.0/11", "118.176.0.0/12", "118.192.0.0/11", "118.244.0.0/14", "118.248.0.0/13",
		"119.0.0.0/12", "119.16.0.0/13", "119.28.0.0/15", "119.29.29.29/32", "119.32.0.0/12", "119.48.0.0/12", "119.84.0.0/14", "119.96.0.0/12", "119.112.0.0/12", "119.128.0.0/11", "119.160.0.0/12", "119.176.0.0/12",
		"120.0.0.0/11", "120.32.0.0/11", "120.64.0.0/11", "120.128.0.0/11", "120.192.0.0/10",
		"121.0.16.0/20", "121.8.0.0/13", "121.16.0.0/12", "121.32.0.0/13", "121.40.0.0/14", "121.48.0.0/12", "121.64.0.0/12", "121.192.0.0/12", "121.208.0.0/12", "121.224.0.0/11",
		"122.0.0.0/11", "122.48.0.0/12", "122.64.0.0/11", "122.96.0.0/12", "122.112.0.0/13", "122.136.0.0/13", "122.144.0.0/12", "122.160.0.0/11", "122.192.0.0/11", "122.224.0.0/12", "122.240.0.0/12",
		"123.0.128.0/17", "123.4.0.0/14", "123.8.0.0/13", "123.48.0.0/12", "123.64.0.0/11", "123.96.0.0/11", "123.128.0.0/11", "123.160.0.0/11", "123.196.0.0/14", "123.232.0.0/13", "123.244.0.0/14",
		"124.0.0.0/12", "124.16.0.0/13", "124.64.0.0/11", "124.96.0.0/11", "124.128.0.0/11", "124.160.0.0/12", "124.192.0.0/12", "124.224.0.0/12", "124.240.0.0/12",
		"125.32.0.0/11", "125.64.0.0/11", "125.96.0.0/12", "125.112.0.0/12", "125.160.0.0/11", "125.192.0.0/11",
		"139.0.0.0/13", "139.128.0.0/12", "139.196.0.0/14", "139.200.0.0/13", "139.208.0.0/12", "139.224.0.0/14",
		"140.206.0.0/15", "140.237.0.0/16", "140.240.0.0/12",
		"171.8.0.0/13", "171.16.0.0/12", "171.32.0.0/12", "171.80.0.0/13", "171.88.0.0/13", "171.104.0.0/12", "171.120.0.0/14", "171.208.0.0/12",
		"175.0.0.0/11", "175.40.0.0/13", "175.48.0.0/12", "175.144.0.0/12", "175.160.0.0/12", "175.176.0.0/14",
		"180.76.0.0/16", "180.96.0.0/11", "180.128.0.0/10", "180.192.0.0/12",
		"182.16.0.0/12", "182.32.0.0/12", "182.48.0.0/13", "182.64.0.0/12", "182.80.0.0/12", "182.96.0.0/12", "182.112.0.0/12", "182.128.0.0/11", "182.240.0.0/12",
		"183.0.0.0/10", "183.64.0.0/12", "183.92.0.0/13", "183.128.0.0/10", "183.192.0.0/10",
		"202.96.0.0/12", "202.112.0.0/12", "202.192.0.0/12",
		"211.80.0.0/12", "211.96.0.0/12", "211.136.0.0/13", "211.144.0.0/12", "211.160.0.0/13",
		"218.0.0.0/10", "218.64.0.0/11", "218.96.0.0/12", "218.104.0.0/13", "218.192.0.0/12", "218.240.0.0/12",
		"219.128.0.0/11", "219.216.0.0/12", "219.232.0.0/12",
		"220.160.0.0/11", "220.192.0.0/11", "220.224.0.0/12", "220.248.0.0/13",
		"221.0.0.0/12", "221.128.0.0/12", "221.176.0.0/12", "221.192.0.0/11", "221.224.0.0/12",
		"222.16.0.0/12", "222.32.0.0/11", "222.64.0.0/10", "222.128.0.0/11", "222.160.0.0/11", "222.192.0.0/12", "222.208.0.0/12", "222.240.0.0/12",
		"223.4.0.0/14", "223.5.5.5/32", "223.6.6.6/32", "223.64.0.0/11", "223.96.0.0/12", "223.112.0.0/12", "223.144.0.0/12", "223.160.0.0/13", "223.192.0.0/12", "223.208.0.0/12", "223.240.0.0/12",
	}

	raw := make([]ipRange, 0, len(cidrs))
	for _, s := range cidrs {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		lo := binary.BigEndian.Uint32(ip4)
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		hi := lo | ^mask
		raw = append(raw, ipRange{lo: lo, hi: hi})
	}
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].lo == raw[j].lo {
			return raw[i].hi < raw[j].hi
		}
		return raw[i].lo < raw[j].lo
	})
	merged := make([]ipRange, 0, len(raw))
	for _, r := range raw {
		n := len(merged)
		if n > 0 && uint64(merged[n-1].hi)+1 >= uint64(r.lo) {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return &Router{cnRanges: merged}
}

func (r *Router) isDirectIPv4(ip4 net.IP) bool {
	v := binary.BigEndian.Uint32(ip4)
	idx := sort.Search(len(r.cnRanges), func(i int) bool {
		return r.cnRanges[i].hi >= v
	})
	return idx < len(r.cnRanges) && r.cnRanges[idx].lo <= v
}

var cnIPv6CIDRs = func() []*net.IPNet {
	list := []string{
		"::1/128", "fc00::/7", "fe80::/10",
		"2408::/20", "2409::/20", "240e::/20", "2400:3200::/32", "2402:4e00::/32", "2001:da8::/32", "2001:250::/32",
	}
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

var cnDomainSuffixes = []string{
	".cn",
	".localhost", ".local", ".lan", ".internal",
	"baidu.com", "bdstatic.com", "baidustatic.com",
	"qq.com", "gtimg.cn", "weixin.qq.com", "qpic.cn", "wechat.com",
	"taobao.com", "tmall.com", "alicdn.com", "aliyun.com", "aliyuncs.com", "alipay.com", "alipayobjects.com", "mmstat.com",
	"jd.com", "360buyimg.com", "jdcloud.com",
	"163.com", "126.com", "126.net", "netease.com",
	"bilibili.com", "hdslb.com", "bilivideo.com",
	"zhihu.com", "zhimg.com",
	"douyin.com", "toutiao.com", "bytedance.com", "byteimg.com", "snssdk.com", "ixigua.com",
	"weibo.com", "sinaimg.cn", "sina.com.cn",
	"mi.com", "xiaomi.com", "xiaomi.net",
	"huawei.com", "huaweicloud.com",
	"qcloud.com", "myqcloud.com",
	"csdn.net", "cnblogs.com", "jianshu.com", "gitee.com",
	"meituan.com", "dianping.com", "pinduoduo.com", "yangkeduo.com",
	"iqiyi.com", "youku.com", "mgtv.com", "cctv.com",
	"bing.cn", "msn.cn", "office365.cn",
}

func isCNDomain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" {
		return true
	}
	for _, sfx := range cnDomainSuffixes {
		if strings.HasPrefix(sfx, ".") {
			if strings.HasSuffix(h, sfx) {
				return true
			}
		} else if h == sfx || strings.HasSuffix(h, "."+sfx) {
			return true
		}
	}
	return false
}

// Decide evaluates destination hostport under mode WITHOUT calling DNS lookup on domains.
func (r *Router) Decide(mode RouteMode, hostport string) RouteAction {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))

	// Internal management domain ALWAYS goes through the GhostFrame tunnel.
	if strings.EqualFold(host, "gft.internal.panel") {
		return ActionProxy
	}

	switch mode {
	case RouteCore, RouteDirect, RouteGlobal:
		// Keep loopback direct so local GUI/apps never loop into VPS; everything else uses tunnel.
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return ActionDirect
		}
		if strings.EqualFold(host, "localhost") {
			return ActionDirect
		}
		return ActionProxy
	default: // RouteRule
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				if r.isDirectIPv4(ip4) {
					return ActionDirect
				}
				return ActionProxy
			}
			for _, n := range cnIPv6CIDRs {
				if n.Contains(ip) {
					return ActionDirect
				}
			}
			return ActionProxy
		}
		if isCNDomain(host) {
			return ActionDirect
		}
		// Never do local DNS lookup on overseas/unknown domains! Send raw hostname via tunnel.
		return ActionProxy
	}
}
