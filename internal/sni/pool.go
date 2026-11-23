package sni

import (
	"encoding/json"
	"os"
)

const DefaultCandidatesPath = "/etc/kestrel/sni_candidates.json"

const legacyCandidatesPath = "/etc/gft/sni_candidates.json"

// DefaultRegionalPool contains verified, high-reputation, non-CDN university/research
// TLS 1.3 + HTTP/2 origins grouped by geographic region.
var DefaultRegionalPool = map[string][]string{
	"APAC-JP-KR": {
		"ftp.jaist.ac.jp",
		"ftp.tsukuba.wide.ad.jp",
		"ftp.riken.jp",
		"ftp.yz.yamagata-u.ac.jp",
		"ftp.nara.wide.ad.jp",
		"mirror.kaist.ac.kr",
		"ftp.harukasan.org",
	},
	"APAC-SG-HK": {
		"download.nus.edu.sg",
		"mirror.cuhk.edu.hk",
		"ftp.HKU.HK",
		"mirror.twds.com.tw",
		"free.nchc.org.tw",
	},
	"NA": {
		"mirror.arizona.edu",
		"mirrors.mit.edu",
		"mirrors.ocf.berkeley.edu",
		"ftp.osuosl.org",
		"mirror.csclub.uwaterloo.ca",
		"mirrors.rit.edu",
		"plug-mirror.rcac.purdue.edu",
	},
	"EU": {
		"ftp.fau.de",
		"ftp.halifax.rwth-aachen.de",
		"ftp.acc.umu.se",
		"mirror.init7.net",
		"ftp.belnet.be",
		"ftp.heanet.ie",
		"mirrors.dotsrc.org",
	},
}

// OrderedRegions defines deterministic iteration order across regions.
var OrderedRegions = []string{"APAC-JP-KR", "APAC-SG-HK", "NA", "EU"}

// Candidate represents one SNI target with its region label.
type Candidate struct {
	Region string `json:"region"`
	Domain string `json:"domain"`
}

// LoadPool returns a fresh copy of the default pool merged with any custom JSON file at extraPath.
func LoadPool(extraPath string) map[string][]string {
	out := make(map[string][]string, len(DefaultRegionalPool))
	seen := make(map[string]bool)
	for reg, list := range DefaultRegionalPool {
		cp := make([]string, 0, len(list))
		for _, d := range list {
			cp = append(cp, d)
			seen[reg+"|"+d] = true
		}
		out[reg] = cp
	}
	var b []byte
	var err error
	if extraPath == "" {
		b, err = os.ReadFile(DefaultCandidatesPath)
		if err != nil {
			b, err = os.ReadFile(legacyCandidatesPath)
		}
	} else {
		b, err = os.ReadFile(extraPath)
	}
	if err != nil {
		return out
	}
	var custom map[string][]string
	if json.Unmarshal(b, &custom) != nil {
		return out
	}
	for reg, list := range custom {
		for _, d := range list {
			if d != "" && !seen[reg+"|"+d] {
				out[reg] = append(out[reg], d)
				seen[reg+"|"+d] = true
			}
		}
	}
	return out
}

// FlattenPool flattens a regional pool into a deterministic slice of Candidate entries.
func FlattenPool(pool map[string][]string) []Candidate {
	var all []Candidate
	seenReg := make(map[string]bool)
	for _, reg := range OrderedRegions {
		seenReg[reg] = true
		for _, dom := range pool[reg] {
			all = append(all, Candidate{Region: reg, Domain: dom})
		}
	}
	for reg, list := range pool {
		if seenReg[reg] {
			continue
		}
		for _, dom := range list {
			all = append(all, Candidate{Region: reg, Domain: dom})
		}
	}
	return all
}
