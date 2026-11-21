package client

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

//go:embed cn_domains.zlib
var cnDomainsZlib []byte

var (
	cnDomainsOnce sync.Once
	cnDomainsMap  map[string]struct{}
)

func loadCNDomainsSet() map[string]struct{} {
	cnDomainsOnce.Do(func() {
		if len(cnDomainsZlib) == 0 {
			return
		}
		zr, err := zlib.NewReader(bytes.NewReader(cnDomainsZlib))
		if err != nil {
			return
		}
		defer zr.Close()
		raw, err := io.ReadAll(io.LimitReader(zr, 4<<20))
		if err != nil || len(raw) == 0 {
			return
		}
		s := string(raw)
		m := make(map[string]struct{}, 4600)
		start := 0
		for i := 0; i <= len(s); i++ {
			if i == len(s) || s[i] == '\n' {
				if i > start {
					line := strings.TrimSpace(s[start:i])
					if line != "" {
						m[line] = struct{}{}
					}
				}
				start = i + 1
			}
		}
		cnDomainsMap = m
	})
	return cnDomainsMap
}

// BuiltinRuleSetVersion identifies the embedded multi-category domain & CIDR rule engine.
const BuiltinRuleSetVersion = "v4.2-SmartRuleSet"

// RuleStats captures embedded rule capacities and cumulative per-action decision hits.
type RuleStats struct {
	Version        string `json:"ruleset_version"`
	BuiltinDomains int    `json:"builtin_domains"`
	BuiltinCIDRs   int    `json:"builtin_cidrs"`
	CustomRules    int    `json:"custom_rules"`
	DirectHits     uint64 `json:"direct_hits"`
	ProxyHits      uint64 `json:"proxy_hits"`
	RejectHits     uint64 `json:"reject_hits"`
}

// CustomRule defines a user-supplied override rule loaded from rules.txt or ClientConfig.CustomRules.
type CustomRule struct {
	Type   string
	Value  string
	Action RouteAction
	CIDR   *net.IPNet
	Tag    string
}

type ruleSeed struct {
	domain string
	tag    string
}

// ParseCustomRules parses Surge/Clash/Shadowrocket style lines:
//   DOMAIN,example.com,DIRECT|PROXY|REJECT
//   DOMAIN-SUFFIX,example.org,PROXY
//   DOMAIN-KEYWORD,ads,REJECT
//   IP-CIDR,1.2.3.0/24,DIRECT[,no-resolve]
func ParseCustomRules(lines []string) []CustomRule {
	var out []CustomRule
	for _, raw := range lines {
		ln := raw
		if idx := strings.Index(ln, "#"); idx >= 0 {
			ln = ln[:idx]
		}
		if idx := strings.Index(ln, "//"); idx >= 0 {
			ln = ln[:idx]
		}
		if idx := strings.Index(ln, ";"); idx >= 0 {
			ln = ln[:idx]
		}
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.Split(ln, ",")
		if len(parts) < 3 {
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		actStr := strings.ToUpper(strings.TrimSpace(parts[2]))
		if typ == "" || val == "" {
			continue
		}

		var act RouteAction
		switch actStr {
		case "DIRECT":
			act = ActionDirect
		case "PROXY", "KSL", "KESTREL":
			act = ActionProxy
		case "REJECT", "BLOCK", "DROP":
			act = ActionReject
		default:
			continue
		}

		tag := "custom:" + strings.ToLower(typ)
		switch typ {
		case "DOMAIN", "DOMAIN-SUFFIX":
			v := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(val), "."), ".")
			if v == "" {
				continue
			}
			out = append(out, CustomRule{Type: typ, Value: v, Action: act, Tag: tag})
		case "DOMAIN-KEYWORD":
			v := strings.ToLower(val)
			out = append(out, CustomRule{Type: typ, Value: v, Action: act, Tag: tag})
		case "IP-CIDR", "IP-CIDR6":
			spec := val
			if !strings.Contains(spec, "/") {
				if ip := net.ParseIP(spec); ip != nil {
					if ip.To4() != nil {
						spec += "/32"
					} else {
						spec += "/128"
					}
				}
			}
			_, ipNet, err := net.ParseCIDR(spec)
			if err != nil {
				continue
			}
			out = append(out, CustomRule{Type: "IP-CIDR", Value: spec, Action: act, CIDR: ipNet, Tag: tag})
		}
	}
	return out
}

// LoadCustomRulesFile reads and parses rules from disk (returns nil if missing/unreadable).
func LoadCustomRulesFile(path string) []CustomRule {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParseCustomRules(strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"))
}

var builtinLanSuffixes = []string{
	"localhost",
	"local",
	"lan",
	"home.arpa",
	"internal",
	"localdomain",
}

var builtinProxyRules = []ruleSeed{
	// AI & LLM Platforms
	{"openai.com", "proxy:ai"},
	{"chatgpt.com", "proxy:ai"},
	{"oaistatic.com", "proxy:ai"},
	{"oaiusercontent.com", "proxy:ai"},
	{"auth0.com", "proxy:ai"},
	{"anthropic.com", "proxy:ai"},
	{"claude.ai", "proxy:ai"},
	{"claudeusercontent.com", "proxy:ai"},
	{"gemini.google.com", "proxy:ai"},
	{"aistudio.google.com", "proxy:ai"},
	{"generativelanguage.googleapis.com", "proxy:ai"},
	{"ai.google.dev", "proxy:ai"},
	{"deepmind.google", "proxy:ai"},
	{"notebooklm.google.com", "proxy:ai"},
	{"perplexity.ai", "proxy:ai"},
	{"x.ai", "proxy:ai"},
	{"grok.com", "proxy:ai"},
	{"cursor.sh", "proxy:ai"},
	{"cursor.com", "proxy:ai"},
	{"cursor-cdn.com", "proxy:ai"},
	{"codeium.com", "proxy:ai"},
	{"windsurf.com", "proxy:ai"},
	{"huggingface.co", "proxy:ai"},
	{"hf.co", "proxy:ai"},
	{"poe.com", "proxy:ai"},
	{"midjourney.com", "proxy:ai"},
	{"civitai.com", "proxy:ai"},
	{"replicate.com", "proxy:ai"},
	{"groq.com", "proxy:ai"},
	{"mistral.ai", "proxy:ai"},
	{"cohere.com", "proxy:ai"},

	// Google Ecosystem & YouTube
	{"google.com", "proxy:google"},
	{"google.com.hk", "proxy:google"},
	{"google.co.jp", "proxy:google"},
	{"googleapis.com", "proxy:google"},
	{"gstatic.com", "proxy:google"},
	{"googleusercontent.com", "proxy:google"},
	{"googlevideo.com", "proxy:google"},
	{"ggpht.com", "proxy:google"},
	{"gvt1.com", "proxy:google"},
	{"gvt2.com", "proxy:google"},
	{"gvt3.com", "proxy:google"},
	{"android.com", "proxy:google"},
	{"chromium.org", "proxy:google"},
	{"chrome.com", "proxy:google"},
	{"golang.org", "proxy:google"},
	{"go.dev", "proxy:google"},
	{"firebase.com", "proxy:google"},
	{"firebaseio.com", "proxy:google"},
	{"youtube.com", "proxy:google"},
	{"ytimg.com", "proxy:google"},
	{"youtu.be", "proxy:google"},
	{"gmail.com", "proxy:google"},
	{"withgoogle.com", "proxy:google"},
	{"recaptcha.net", "proxy:google"},
	{"blogger.com", "proxy:google"},
	{"blogspot.com", "proxy:google"},
	{"googlesource.com", "proxy:google"},

	// Developer, Cloud & Infrastructure
	{"github.com", "proxy:dev"},
	{"githubusercontent.com", "proxy:dev"},
	{"githubassets.com", "proxy:dev"},
	{"github.io", "proxy:dev"},
	{"ghcr.io", "proxy:dev"},
	{"gitlab.com", "proxy:dev"},
	{"bitbucket.org", "proxy:dev"},
	{"stackoverflow.com", "proxy:dev"},
	{"stackexchange.com", "proxy:dev"},
	{"sstatic.net", "proxy:dev"},
	{"docker.com", "proxy:dev"},
	{"docker.io", "proxy:dev"},
	{"npmjs.org", "proxy:dev"},
	{"npmjs.com", "proxy:dev"},
	{"pypi.org", "proxy:dev"},
	{"pythonhosted.org", "proxy:dev"},
	{"crates.io", "proxy:dev"},
	{"rust-lang.org", "proxy:dev"},
	{"pkg.go.dev", "proxy:dev"},
	{"homebrew.sh", "proxy:dev"},
	{"brew.sh", "proxy:dev"},
	{"cloudflare.com", "proxy:dev"},
	{"cloudflare-dns.com", "proxy:dev"},
	{"workers.dev", "proxy:dev"},
	{"pages.dev", "proxy:dev"},
	{"r2.dev", "proxy:dev"},
	{"vercel.com", "proxy:dev"},
	{"vercel.app", "proxy:dev"},
	{"netlify.com", "proxy:dev"},
	{"netlify.app", "proxy:dev"},
	{"amazonaws.com", "proxy:dev"},
	{"awsstatic.com", "proxy:dev"},
	{"azureedge.net", "proxy:dev"},
	{"fastly.net", "proxy:dev"},
	{"fastlylb.net", "proxy:dev"},
	{"jsdelivr.net", "proxy:dev"},
	{"unpkg.com", "proxy:dev"},
	{"archive.org", "proxy:dev"},
	{"adguard.org", "proxy:dev"},

	// Social, Messaging & Community
	{"x.com", "proxy:social"},
	{"twitter.com", "proxy:social"},
	{"twimg.com", "proxy:social"},
	{"t.co", "proxy:social"},
	{"telegram.org", "proxy:social"},
	{"t.me", "proxy:social"},
	{"telegra.ph", "proxy:social"},
	{"tdesktop.com", "proxy:social"},
	{"discord.com", "proxy:social"},
	{"discordapp.com", "proxy:social"},
	{"discordapp.net", "proxy:social"},
	{"discord.gg", "proxy:social"},
	{"reddit.com", "proxy:social"},
	{"redd.it", "proxy:social"},
	{"redditstatic.com", "proxy:social"},
	{"redditmedia.com", "proxy:social"},
	{"facebook.com", "proxy:social"},
	{"fbcdn.net", "proxy:social"},
	{"instagram.com", "proxy:social"},
	{"cdninstagram.com", "proxy:social"},
	{"threads.net", "proxy:social"},
	{"whatsapp.com", "proxy:social"},
	{"whatsapp.net", "proxy:social"},
	{"tiktok.com", "proxy:social"},
	{"tiktokv.com", "proxy:social"},
	{"tiktokcdn.com", "proxy:social"},
	{"line.me", "proxy:social"},
	{"line-scdn.net", "proxy:social"},
	{"linkedin.com", "proxy:social"},
	{"licdn.com", "proxy:social"},
	{"v2ex.com", "proxy:social"},
	{"nodeseek.com", "proxy:social"},
	{"linux.do", "proxy:social"},
	{"medium.com", "proxy:social"},
	{"substack.com", "proxy:social"},
	{"quora.com", "proxy:social"},
	{"pinterest.com", "proxy:social"},
	{"pinimg.com", "proxy:social"},

	// Knowledge, Streaming, Media & Gaming Storefronts
	{"wikipedia.org", "proxy:global"},
	{"wikimedia.org", "proxy:global"},
	{"wiktionary.org", "proxy:global"},
	{"netflix.com", "proxy:streaming"},
	{"nflxvideo.net", "proxy:streaming"},
	{"nflximg.net", "proxy:streaming"},
	{"nflxext.com", "proxy:streaming"},
	{"disneyplus.com", "proxy:streaming"},
	{"bamgrid.com", "proxy:streaming"},
	{"spotify.com", "proxy:streaming"},
	{"scdn.co", "proxy:streaming"},
	{"twitch.tv", "proxy:streaming"},
	{"ttvnw.net", "proxy:streaming"},
	{"soundcloud.com", "proxy:streaming"},
	{"vimeo.com", "proxy:streaming"},
	{"dailymotion.com", "proxy:streaming"},
	{"pixiv.net", "proxy:streaming"},
	{"pximg.net", "proxy:streaming"},
	{"steampowered.com", "proxy:global"},
	{"steamcommunity.com", "proxy:global"},
	{"steamstatic.com", "proxy:global"},
	{"playstation.com", "proxy:global"},
	{"playstation.net", "proxy:global"},
	{"nintendo.com", "proxy:global"},
	{"nintendo.net", "proxy:global"},
	{"nytimes.com", "proxy:global"},
	{"bbc.com", "proxy:global"},
	{"bbci.co.uk", "proxy:global"},
	{"reuters.com", "proxy:global"},
	{"bloomberg.com", "proxy:global"},
	{"wsj.com", "proxy:global"},
	{"economist.com", "proxy:global"},
	{"tradingview.com", "proxy:global"},
	{"binance.com", "proxy:global"},
	{"okx.com", "proxy:global"},
	{"coinbase.com", "proxy:global"},
	{"dropbox.com", "proxy:global"},
	{"notion.so", "proxy:global"},
	{"figma.com", "proxy:global"},
	{"canva.com", "proxy:global"},
	{"mega.nz", "proxy:global"},
	{"mask.icloud.com", "proxy:global"},
	{"mask-h2.icloud.com", "proxy:global"},

	// IP / DNS Leak Test & VPN Diagnostic Sites (must NEVER leak direct DNS)
	{"ping0.cc", "proxy:leak-check"},
	{"ipleak.net", "proxy:leak-check"},
	{"dnsleaktest.com", "proxy:leak-check"},
	{"browserleaks.com", "proxy:leak-check"},
	{"bash.ws", "proxy:leak-check"},
	{"whoer.net", "proxy:leak-check"},
	{"ip-api.com", "proxy:leak-check"},
	{"ipinfo.io", "proxy:leak-check"},
	{"ip.sb", "proxy:leak-check"},
	{"ipify.org", "proxy:leak-check"},
	{"ident.me", "proxy:leak-check"},
	{"scamalytics.com", "proxy:leak-check"},
	{"ipdata.co", "proxy:leak-check"},
	{"ipgeolocation.io", "proxy:leak-check"},
	{"astrill.com", "proxy:leak-check"},
	{"expressvpn.com", "proxy:leak-check"},
	{"surfshark.com", "proxy:leak-check"},
	{"mullvad.net", "proxy:leak-check"},
	{"cloudflareclient.com", "proxy:leak-check"},

	// Domestic Public DoH Endpoints (prevent browser DoH from bypassing tunnel rules)
	{"dns.alidns.com", "proxy:doh-guard"},
	{"doh.pub", "proxy:doh-guard"},
	{"sm2.doh.pub", "proxy:doh-guard"},
	{"dot.pub", "proxy:doh-guard"},
	{"dns.pub", "proxy:doh-guard"},
	{"doh.360.cn", "proxy:doh-guard"},
}

var builtinDirectRules = []ruleSeed{
	// Tencent / WeChat / QQ
	{"qq.com", "direct:cn"},
	{"gtimg.cn", "direct:cn"},
	{"gtimg.com", "direct:cn"},
	{"qpic.cn", "direct:cn"},
	{"qlogo.cn", "direct:cn"},
	{"weixin.com", "direct:cn"},
	{"wechat.com", "direct:cn"},
	{"wx.qq.com", "direct:cn"},
	{"servicewechat.com", "direct:cn"},
	{"weixinbridge.com", "direct:cn"},
	{"wx.qlogo.cn", "direct:cn"},
	{"tenpay.com", "direct:cn"},
	{"myqcloud.com", "direct:cn-cloud"},
	{"qcloud.com", "direct:cn-cloud"},
	{"qcloudcdn.com", "direct:cn-cloud"},
	{"cdntips.com", "direct:cn-cloud"},
	{"ugdtimg.com", "direct:cn"},
	{"gdtimg.com", "direct:cn"},
	{"tencentcos.cn", "direct:cn-cloud"},
	{"dnspod.cn", "direct:cn-cloud"},
	{"smtcdns.net", "direct:cn-cloud"},
	{"tencent.com", "direct:cn"},
	{"tencent-cloud.com", "direct:cn-cloud"},

	// Alibaba / Taobao / Alipay / Aliyun / Alipan / Amap / DingTalk
	{"taobao.com", "direct:cn"},
	{"tmall.com", "direct:cn"},
	{"alicdn.com", "direct:cn-cloud"},
	{"aliyun.com", "direct:cn-cloud"},
	{"aliyuncs.com", "direct:cn-cloud"},
	{"alipay.com", "direct:cn"},
	{"alipayobjects.com", "direct:cn"},
	{"alipan.com", "direct:cn"},
	{"aliyundrive.com", "direct:cn"},
	{"mmstat.com", "direct:cn"},
	{"1688.com", "direct:cn"},
	{"amap.com", "direct:cn"},
	{"autonavi.com", "direct:cn"},
	{"dingtalk.com", "direct:cn"},
	{"cainiao.com", "direct:cn"},
	{"ele.me", "direct:cn"},
	{"elemecdn.com", "direct:cn"},
	{"fliggy.com", "direct:cn"},
	{"youku.com", "direct:cn"},
	{"tudou.com", "direct:cn"},
	{"yuque.com", "direct:cn"},

	// ByteDance / Douyin / Feishu / Toutiao / Doubao
	{"douyin.com", "direct:cn"},
	{"douyincdn.com", "direct:cn"},
	{"toutiao.com", "direct:cn"},
	{"bytedance.com", "direct:cn"},
	{"byteimg.com", "direct:cn"},
	{"bytetos.com", "direct:cn"},
	{"bytecdntp.com", "direct:cn-cloud"},
	{"alikunlun.com", "direct:cn-cloud"},
	{"kunlunca.com", "direct:cn-cloud"},
	{"kunlunar.com", "direct:cn-cloud"},
	{"snssdk.com", "direct:cn"},
	{"ixigua.com", "direct:cn"},
	{"feishu.cn", "direct:cn"},
	{"volcengine.com", "direct:cn-cloud"},
	{"volces.com", "direct:cn-cloud"},
	{"doubao.com", "direct:cn-ai"},

	// Baidu / JD / Pinduoduo / Meituan / Xiaohongshu / Bilibili / Kuaishou
	{"baidu.com", "direct:cn"},
	{"bdstatic.com", "direct:cn"},
	{"baidustatic.com", "direct:cn"},
	{"bcebos.com", "direct:cn-cloud"},
	{"jd.com", "direct:cn"},
	{"360buyimg.com", "direct:cn"},
	{"jdcloud.com", "direct:cn-cloud"},
	{"pinduoduo.com", "direct:cn"},
	{"yangkeduo.com", "direct:cn"},
	{"meituan.com", "direct:cn"},
	{"meituan.net", "direct:cn"},
	{"dianping.com", "direct:cn"},
	{"xiaohongshu.com", "direct:cn"},
	{"xhscdn.com", "direct:cn"},
	{"bilibili.com", "direct:cn"},
	{"hdslb.com", "direct:cn"},
	{"bilivideo.com", "direct:cn"},
	{"biliapi.net", "direct:cn"},
	{"kuaishou.com", "direct:cn"},
	{"yximgs.com", "direct:cn"},

	// NetEase / Zhihu / Douban / Weibo / Video / Music / News
	{"163.com", "direct:cn"},
	{"126.com", "direct:cn"},
	{"126.net", "direct:cn"},
	{"netease.com", "direct:cn"},
	{"zhihu.com", "direct:cn"},
	{"zhimg.com", "direct:cn"},
	{"douban.com", "direct:cn"},
	{"doubanio.com", "direct:cn"},
	{"weibo.com", "direct:cn"},
	{"sinaimg.cn", "direct:cn"},
	{"sina.com.cn", "direct:cn"},
	{"iqiyi.com", "direct:cn"},
	{"qiyipic.com", "direct:cn"},
	{"mgtv.com", "direct:cn"},
	{"cctv.com", "direct:cn"},
	{"huya.com", "direct:cn"},
	{"douyu.com", "direct:cn"},
	{"ximalaya.com", "direct:cn"},
	{"kugou.com", "direct:cn"},
	{"kuwo.cn", "direct:cn"},

	// Domestic AI Models & Tech / Mirrors / Office
	{"deepseek.com", "direct:cn-ai"},
	{"kimi.ai", "direct:cn-ai"},
	{"moonshot.cn", "direct:cn-ai"},
	{"qwen.ai", "direct:cn-ai"},
	{"bigmodel.cn", "direct:cn-ai"},
	{"zhipuai.cn", "direct:cn-ai"},
	{"minimaxi.com", "direct:cn-ai"},
	{"wps.cn", "direct:cn"},
	{"wpscdn.cn", "direct:cn"},
	{"csdn.net", "direct:cn"},
	{"cnblogs.com", "direct:cn"},
	{"jianshu.com", "direct:cn"},
	{"gitee.com", "direct:cn"},
	{"juejin.cn", "direct:cn"},
	{"ithome.com", "direct:cn"},
	{"36kr.com", "direct:cn"},
	{"sspai.com", "direct:cn"},
	{"chiphell.com", "direct:cn"},
	{"oschina.net", "direct:cn"},
	{"npmmirror.com", "direct:cn-cloud"},

	// Domestic Hardware / EV / Travel / Logistics / Finance / Games
	{"mi.com", "direct:cn"},
	{"xiaomi.com", "direct:cn"},
	{"xiaomi.net", "direct:cn"},
	{"huawei.com", "direct:cn"},
	{"huaweicloud.com", "direct:cn-cloud"},
	{"myhuaweicloud.com", "direct:cn-cloud"},
	{"cdnhwc1.com", "direct:cn-cloud"},
	{"cdnhwc2.com", "direct:cn-cloud"},
	{"oppo.com", "direct:cn"},
	{"heytap.com", "direct:cn"},
	{"vivo.com", "direct:cn"},
	{"lenovo.com", "direct:cn"},
	{"dji.com", "direct:cn"},
	{"byd.com", "direct:cn"},
	{"nio.com", "direct:cn"},
	{"xiaopeng.com", "direct:cn"},
	{"lixiang.com", "direct:cn"},
	{"ctrip.com", "direct:cn"},
	{"12306.cn", "direct:cn"},
	{"didiglobal.com", "direct:cn"},
	{"xiaojukeji.com", "direct:cn"},
	{"sf-express.com", "direct:cn"},
	{"eastmoney.com", "direct:cn"},
	{"xueqiu.com", "direct:cn"},
	{"mihoyo.com", "direct:cn"},
	{"hoyoverse.com", "direct:cn"},
	{"hypergryph.com", "direct:cn"},
	{"taptap.cn", "direct:cn"},
	{"taptap.com", "direct:cn"},
	{"tapimg.com", "direct:cn"},
	{"4399.com", "direct:cn"},
	{"7k7k.com", "direct:cn"},
	{"hortorgames.com", "direct:cn"},
	{"tuyoo.com", "direct:cn"},
	{"jj.cn", "direct:cn"},
	{"sanguosha.com", "direct:cn"},
	{"leiting.com", "direct:cn"},
	{"lilithgames.com", "direct:cn"},
	{"nga.cn", "direct:cn"},
	{"ngacn.cc", "direct:cn"},

	// Domestic CDN / Cloud
	{"qiniucdn.com", "direct:cn-cloud"},
	{"qiniudns.com", "direct:cn-cloud"},
	{"upaiyun.com", "direct:cn-cloud"},
	{"ksyun.com", "direct:cn-cloud"},
	{"ctyun.cn", "direct:cn-cloud"},
	{"ucloud.cn", "direct:cn-cloud"},
	{"bing.cn", "direct:cn"},
	{"msn.cn", "direct:cn"},
	{"office365.cn", "direct:cn"},

	// Apple CN Services & Download CDNs
	{"apple-cloudkit.cn", "direct:apple-cn"},
	{"icloud.com.cn", "direct:apple-cn"},
	{"icloud-content.com.cn", "direct:apple-cn"},
	{"cdn-apple.com", "direct:apple-cn"},
	{"mzstatic.com", "direct:apple-cn"},
	{"aaplimg.com", "direct:apple-cn"},
	{"appstore.com", "direct:apple-cn"},

	// Microsoft CN / Windows Update / VSCode CN
	{"msftconnecttest.com", "direct:ms-cn"},
	{"msftncsi.com", "direct:ms-cn"},
	{"windowsupdate.com", "direct:ms-cn"},
	{"update.microsoft.com", "direct:ms-cn"},
	{"dl.delivery.mp.microsoft.com", "direct:ms-cn"},
	{"vscode.cdn.azure.cn", "direct:ms-cn"},
	{"azure.cn", "direct:ms-cn"},

	// Steam CN Download CDN (Storefront stays Proxy via steampowered.com)
	{"steamcontent.com", "direct:steam-cn"},
	{"steamserver.net", "direct:steam-cn"},
	{"st.dl.eccdnx.com", "direct:steam-cn"},
	{"st.dl.pinyuncloud.com", "direct:steam-cn"},
}
