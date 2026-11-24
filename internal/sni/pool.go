package sni

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
)

const DefaultCandidatesPath = "/etc/kestrel/sni_candidates.json"

const legacyCandidatesPath = "/etc/gft/sni_candidates.json"

// DefaultRegionalPool contains 350+ live-verified, diverse, non-CDN TLS 1.3 + HTTP/2
// independent origins (municipalities, transit/ports/airports, water/energy utilities,
// IXPs, regional registries, ISPs, datacenters, libraries, museums, observatories,
// research centers, open-source foundations, and regional mirrors) grouped by region.
var DefaultRegionalPool = map[string][]string{
	"APAC-JP-KR": {
		// IXPs, ISPs, registries, transit, airports, public & niche tech portals (Japan & Korea)
		"www.jpix.ad.jp",
		"www.mfeed.ad.jp",
		"www.asahi-net.or.jp",
		"www.plala.or.jp",
		"www.4gamer.net",
		"www.jaxa.jp",
		"www.nhk.or.jp",
		"www.westjr.co.jp",
		"www.kansai-airport.or.jp",
		"www.cafe24.com",
		"www.kakaocorp.com",
		"www.nii.ac.jp",
		"www.kyoto-u.ac.jp",
		"www.kyushu-u.ac.jp",
		"www.titech.ac.jp",
		"www.aoyama.ac.jp",
		"www.chiba-u.ac.jp",
		"www.chuo-u.ac.jp",
		"www.hiroshima-u.ac.jp",
		"www.hosei.ac.jp",
		"www.kanazawa-u.ac.jp",
		"www.ritsumei.ac.jp",
		"www.ynu.ac.jp",
		"www.uos.ac.kr",
		// Independent regional mirrors
		"mirror.xtom.jp",
		"mirror.navercorp.com",
		"mirror.siwoo.org",
		"ftp.tsukuba.wide.ad.jp",
		"ftp.jaist.ac.jp",
		"ftp.riken.jp",
		"ftp.yz.yamagata-u.ac.jp",
		"ftp.nara.wide.ad.jp",
		"ftp.kaist.ac.kr",
		"ftp.lanet.kr",
	},
	"APAC-SG-HK": {
		// HK / SG / TW / AU ISPs, IXPs, transit, utilities, registries, agencies & tech parks
		"www.hkbn.net",
		"www.hkstp.org",
		"www.hko.gov.hk",
		"www.hkma.gov.hk",
		"www.hkex.com.hk",
		"www.mtr.com.hk",
		"www.starferry.com.hk",
		"www.clp.com.hk",
		"www.hkjc.com",
		"www.gov.hk",
		"www.ogcio.gov.hk",
		"www.hkpl.gov.hk",
		"www.epd.gov.hk",
		"www.immd.gov.hk",
		"www.ird.gov.hk",
		"www.td.gov.hk",
		"www.lta.gov.sg",
		"www.smrt.com.sg",
		"www.spgroup.com.sg",
		"www.sgh.com.sg",
		"www.nyp.edu.sg",
		"www.tp.edu.sg",
		"www.twnic.tw",
		"www.npm.gov.tw",
		"www.ix.asn.au",
		"www.hku.hk",
		"www.ust.hk",
		"www.hkbu.edu.hk",
		"www.ncku.edu.tw",
		"www.ncu.edu.tw",
		"www.ntust.edu.tw",
		// Independent regional mirrors
		"mirror.xtom.com.hk",
		"mirror.sg.gs",
		"mirror.freedif.org",
		"download.nus.edu.sg",
		"mirror.cuhk.edu.hk",
		"mirror.twds.com.tw",
		"free.nchc.org.tw",
		"mirror.aarnet.edu.au",
	},
	"NA-WEST": {
		// Los Angeles / SoCal / Orange County / San Diego datacenters, IXPs, civic, utilities, transit & institutions
		"www.any2.net",
		"www.quadranet.com",
		"www.multacom.com",
		"www.nlayer.net",
		"www.zayo.com",
		"www.cenic.org",
		"www.icann.org",
		"www.lacity.org",
		"www.cityofpasadena.net",
		"www.culvercity.org",
		"www.torranceca.gov",
		"www.redondo.org",
		"www.cityofirvine.org",
		"www.santa-ana.org",
		"www.cityofrc.us",
		"www.ontarioca.gov",
		"www.claremontca.gov",
		"www.southpasadenaca.gov",
		"www.sandimasca.gov",
		"www.cityofwalnut.org",
		"www.danapoint.org",
		"www.san-clemente.org",
		"www.ggcity.org",
		"www.ocgov.com",
		"www.ocair.com",
		"www.polb.com",
		"www.ventura.org",
		"www.sandiegocounty.gov",
		"www.sandag.org",
		"www.sdmts.com",
		"www.san-marcos.net",
		"www.sdparks.org",
		"www.laparks.org",
		"www.arboretum.org",
		"www.mtwilson.edu",
		"www.pasadenastarnews.com",
		"www.sce.com",
		"www.irwd.com",
		"www.ocwd.com",
		"www.ocsan.gov",
		"www.emwd.org",
		"www.usc.edu",
		"www.sdsc.edu",
		"www.lmu.edu",
		"www.cpp.edu",
		"www.csulb.edu",
		"www.hmc.edu",
		"www.chapman.edu",
		"www.kgi.edu",
		"www.sandiego.edu",
		"www.pasadena.edu",
		"www.smc.edu",
		"www.laccd.edu",
		"www.lacitycollege.edu",
		"www.elac.edu",
		"www.piercecollege.edu",
		"www.lavc.edu",
		"www.wlac.edu",
		"www.lahc.edu",
		"www.lamission.edu",
		"www.lasc.edu",
		"www.lattc.edu",
		"www.glendale.edu",
		"www.mtsac.edu",
		"www.citruscollege.edu",
		"www.compton.edu",
		"www.nocccd.edu",
		"www.cccd.edu",
		"www.orangecoastcollege.edu",
		"www.goldenwestcollege.edu",
		"www.rcc.edu",
		"www.mvc.edu",
		"www.norcocollege.edu",
		"www.msjc.edu",
		"www.vvc.edu",
		"www.collegeofthedesert.edu",
		"www.hancockcollege.edu",
		// San Jose / Silicon Valley / SF Bay Area / Northern California
		"mirrors.xtom.com",
		"bgp.he.net",
		"www.isc.org",
		"www.sonic.com",
		"www.monkeybrains.net",
		"www.vta.org",
		"www.sjpl.org",
		"www.cupertino.org",
		"www.cityofpaloalto.org",
		"www.menlopark.gov",
		"www.cityofsancarlos.org",
		"www.ssf.net",
		"www.sfport.com",
		"www.oaklandca.gov",
		"www.alamedaca.gov",
		"www.emeryville.org",
		"www.cityofsanrafael.org",
		"www.cityofsantacruz.com",
		"www.cityofsalinas.org",
		"www.mtc.ca.gov",
		"www.baaqmd.gov",
		"www.ebmud.com",
		"www.marinwater.org",
		"www.pge.com",
		"www.smud.org",
		"www.saccounty.gov",
		"www.elkgrovecity.org",
		"www.stocktonca.gov",
		"www.chico.ca.us",
		"www.cityofredding.org",
		"www.parks.ca.gov",
		"www.caloes.ca.gov",
		"www.cdph.ca.gov",
		"www.ftb.ca.gov",
		"www.calacademy.org",
		"www.aclibrary.org",
		"www.ccclib.org",
		"www.smcl.org",
		"www.oaklandlibrary.org",
		"www.berkeleypubliclibrary.org",
		"www.sonomalibrary.org",
		"www.saclibrary.org",
		"www.ucdavis.edu",
		"www.ucmerced.edu",
		"mirrors.ocf.berkeley.edu",
		"www.csueastbay.edu",
		"www.stmarys-ca.edu",
		"www.ndnu.edu",
		"www.cccco.edu",
		"www.4cd.edu",
		"www.evc.edu",
		"www.gavilan.edu",
		"www.ohlone.edu",
		"www.chabotcollege.edu",
		"www.losmedanos.edu",
		"www.santarosa.edu",
		"www.mpc.edu",
		"www.mjc.edu",
		"www.siskiyous.edu",
		// Pacific Northwest / Southwest (WA, OR, AZ, NV, UT, CO, HI, BC)
		"www.washington.edu",
		"www.oregonstate.edu",
		"ftp.osuosl.org",
		"www.fredhutch.org",
		"www.wwu.edu",
		"www.pugetsound.edu",
		"www.spu.edu",
		"www.bellevuewa.gov",
		"www.kirklandwa.gov",
		"www.soundtransit.org",
		"www.beavertonoregon.gov",
		"www.reed.edu",
		"www.up.edu",
		"www.translink.ca",
		"www.phoenix.gov",
		"www.mesaaz.gov",
		"www.glendaleaz.com",
		"www.tucsonaz.gov",
		"www.nau.edu",
		"mirror.arizona.edu",
		"www.unlv.edu",
		"www.unr.edu",
		"www.usu.edu",
		"www.rideuta.com",
		"www.coloradosprings.gov",
		"www.keckobservatory.org",
	},
	"NA": {
		// US Central / US East / Canada civic, transit, libraries, OSS foundations & origins
		"www.internet2.edu",
		"www.postgresql.org",
		"www.archlinux.org",
		"www.debian.org",
		"www.gentoo.org",
		"www.apache.org",
		"mirrors.kernel.org",
		"www.nyc.gov",
		"www.chicago.gov",
		"www.houstontx.gov",
		"www.miamigov.com",
		"www.orlando.gov",
		"www.charlottenc.gov",
		"www.columbus.gov",
		"www.clevelandohio.gov",
		"www.pittsburghpa.gov",
		"www.stpaul.gov",
		"www.mta.info",
		"www.wmata.com",
		"www.nypl.org",
		"www.bpl.org",
		"www.chipublib.org",
		"www.tpl.ca",
		"www.calgary.ca",
		"www.edmonton.ca",
		"www.winnipeg.ca",
		"www.halifax.ca",
		"www.harvard.edu",
		"www.cornell.edu",
		"www.gatech.edu",
		"www.emory.edu",
		"www.umd.edu",
		"www.virginia.edu",
		"www.ufl.edu",
		"www.utexas.edu",
		"www.rice.edu",
		"www.uchicago.edu",
		"www.utoronto.ca",
		"www.uwaterloo.ca",
		"www.queensu.ca",
		"www.uwo.ca",
		"mirrors.mit.edu",
		"mirror.csclub.uwaterloo.ca",
		"mirrors.rit.edu",
		"plug-mirror.rcac.purdue.edu",
	},
	"EU": {
		// RIRs, ccTLD registries, IXPs, transit, civic, weather, libraries, media & EU origins
		"www.ripe.net",
		"www.denic.de",
		"www.sidn.nl",
		"www.afnic.fr",
		"www.nic.cz",
		"www.netnod.se",
		"www.switch.ch",
		"www.dfn.de",
		"www.surf.nl",
		"www.heise.de",
		"www.nikhef.nl",
		"www.inria.fr",
		"www.cnrs.fr",
		"www.cesnet.cz",
		"www.csc.fi",
		"www.belnet.be",
		"www.heanet.ie",
		"mirror.init7.net",
		"mirror.de.leaseweb.net",
		"mirror.nl.leaseweb.net",
		"www.berlin.de",
		"www.muenchen.de",
		"www.duesseldorf.de",
		"www.leipzig.de",
		"www.bvg.de",
		"www.mvg.de",
		"www.rmv.de",
		"www.denhaag.nl",
		"www.eindhoven.nl",
		"www.gvb.nl",
		"www.cbs.nl",
		"www.bl.uk",
		"www.birmingham.gov.uk",
		"www.edinburgh.gov.uk",
		"www.paris.fr",
		"www.lyon.fr",
		"www.marseille.fr",
		"www.toulouse.fr",
		"www.bnf.fr",
		"www.stadt-zuerich.ch",
		"www.meteoswiss.admin.ch",
		"www.wien.gv.at",
		"www.graz.at",
		"www.sl.se",
		"www.smhi.se",
		"www.malmo.se",
		"www.espoo.fi",
		"www.kk.dk",
		"www.aarhus.dk",
		"www.dsb.dk",
		"www.dmi.dk",
		"www.warszawa.pl",
		"www.krakow.pl",
		"www.gdansk.pl",
		"www.madrid.es",
		"www.comune.milano.it",
		"www.cam.ac.uk",
		"www.ed.ac.uk",
		"www.ethz.ch",
		"www.kit.edu",
		"www.kth.se",
		"www.tu-berlin.de",
		"www.uio.no",
		"www.uni-frankfurt.de",
		"www.univie.ac.at",
		"www.uva.nl",
		"ftp.fau.de",
		"ftp.halifax.rwth-aachen.de",
		"ftp.acc.umu.se",
		"ftp.lysator.liu.se",
		"mirrors.dotsrc.org",
	},
}

// OrderedRegions defines deterministic iteration order across regions.
var OrderedRegions = []string{"NA-WEST", "APAC-JP-KR", "APAC-SG-HK", "NA", "EU"}

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

// FlattenPool flattens a regional pool into a deterministic round-robin interleaved slice
// across regions so concurrent probing covers APAC, NA, and EU simultaneously from t=0.
func FlattenPool(pool map[string][]string) []Candidate {
	regions := make([]string, 0, len(pool))
	seenReg := make(map[string]bool, len(pool))
	for _, reg := range OrderedRegions {
		if len(pool[reg]) > 0 {
			regions = append(regions, reg)
			seenReg[reg] = true
		}
	}
	for reg, list := range pool {
		if !seenReg[reg] && len(list) > 0 {
			regions = append(regions, reg)
		}
	}
	maxLen := 0
	for _, reg := range regions {
		if len(pool[reg]) > maxLen {
			maxLen = len(pool[reg])
		}
	}
	var all []Candidate
	for i := 0; i < maxLen; i++ {
		for _, reg := range regions {
			list := pool[reg]
			if i < len(list) {
				all = append(all, Candidate{Region: reg, Domain: list[i]})
			}
		}
	}
	return all
}

// SamplePerRegion randomly selects up to maxPerRegion domains from each region (using crypto/rand)
// and returns them round-robin interleaved across all regions so every probe wave covers all
// geographies evenly while keeping large 300+ pools fast (<5s) and collision-free across installs.
func SamplePerRegion(pool map[string][]string, maxPerRegion int) []Candidate {
	if maxPerRegion <= 0 {
		return FlattenPool(pool)
	}
	sampled := make(map[string][]string, len(pool))
	for reg, list := range pool {
		cp := make([]string, len(list))
		copy(cp, list)
		for i := len(cp) - 1; i > 0; i-- {
			nBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			if err != nil {
				break
			}
			j := int(nBig.Int64())
			cp[i], cp[j] = cp[j], cp[i]
		}
		if len(cp) > maxPerRegion {
			cp = cp[:maxPerRegion]
		}
		sampled[reg] = cp
	}
	return FlattenPool(sampled)
}
