package main

import (
	"fmt"
	"log"
	"net"
	"orbit/cmd"
	"orbit/internal/file_management"
	"orbit/models"
	"orbit/pkg/dns_analysers"
	"orbit/pkg/ip_addresses"
	"orbit/pkg/reporting"
	"orbit/pkg/zone_files"
	"os"
	"regexp"
	"strings"
)

var (
	zones  = zone_files.DNSZones{}
	ipa    = ip_addresses.IPAddresses{}
	rep    = reporting.Reporting{}
	dna    = dns_analysers.DNSAnalyser{}
	assess = models.ASMAssessment{}
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("[!] Failed to parse initialise arguments: ", err.Error())
		log.Print("[!] Exiting...")
		os.Exit(1)
	}

	zf, _ := cmd.RootCmd.PersistentFlags().GetString("iZ")
	if zf != "" {
		getZoneData(zf)
	}

	ips, _ := cmd.RootCmd.PersistentFlags().GetString("iI")
	if ips != "" {
		readIPsFile(ips)
	}

	urlList, _ := cmd.RootCmd.PersistentFlags().GetString("iU")
	if urlList != "" {
		readUrlsFile(urlList)
	}

	// Get IP addresses from A/AAA records
	for i := range assess.Zones {
		aRecs := rep.AandAAARecords(&assess.Zones[i])
		ipa.AddManyIPStrAddresses(aRecs, &assess.IPAddresses)
	}

	// Get aliases
	getAliasesFromZones()

	// Lookup IPs of all known domains and track otherwise unknown IPs
	domainIPLookups()

	processReverseLookups()

	// Review all IP addresses and note any exposed internal IP addresses in records.
	reviewPrivateIPs()

	// Print test data
	printURLTargets()
	printUntrackedIPs()
	printDNSSECMissing()
}

func getZoneData(zf string) {
	zfResults, err := zones.GetZoneData(zf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	assess.Zones = zfResults
}

func readIPsFile(ips string) {
	existingIps, err := file_management.ReadFileLines(ips)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var ipMod models.IPCollection
	for i := range existingIps {
		if ip := net.ParseIP(existingIps[i]); ip != nil {
			if ipa.IsIPv4(ip) {
				ipMod.IPv4 = append(ipMod.IPv4, ip)
			} else {
				ipMod.IPv6 = append(ipMod.IPv6, ip)
			}
		}
	}
	assess.IPAddresses = ipMod
}

func readUrlsFile(urlList string) {
	existingUrls, err := file_management.ReadFileLines(urlList)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for i := range existingUrls {
		assess.Domains = append(assess.Domains, existingUrls[i])
	}
}

func getAliasesFromZones() {
	for _, zone := range assess.Zones {
		aliases := rep.CNAMERecords(&zone)
		// Remove .gtm domains. These are mostly subdomains used elsewhere
		temp := make([]map[string]string, len(aliases))
		re := regexp.MustCompile(`\.gtm$`)
		for i := range aliases {
			for _, val := range aliases[i] {
				if !re.MatchString(val) {
					// Only use values which could be valid domains.
					if len(strings.Split(val, ".")) > 2 {
						temp[i] = aliases[i]
					}
				}
			}
		}
		if len(temp) > 0 {
			aliases = temp
			temp = nil
		}
		if aliases != nil && len(aliases) > 0 {
			al := models.AliasRecords{
				Domain:       zone.Origin,
				Relationship: aliases,
			}
			assess.Aliases = append(assess.Aliases, al)
		}

		// Check for DNSSEC enablement
		if res, _ := dna.DNSSECEnabled(zone.Origin); res {
			rep.AddMissingDNSSec(zone.Origin, &assess)
		}

		ip := net.ParseIP(zone.Origin)
		if ip != nil && !ipa.IPExistsIn(ip, &assess.IPAddresses) {
			ipa.CheckAddIPtoAddresses(ip, &assess.IPAddresses)
		} else {
			fqdns := rep.GetFQDNs(&zone)
			for i := range fqdns {
				rep.AddURLToAsmDomainsDupSafe(fqdns[i], &assess)
			}
		}
	}
}

func processReverseLookups() {
	allowed := []string{"money", "fx", "ttt", "novo", "explore", "currency"}
	for _, ip := range assess.IPAddresses.IPv4 {
		domains, err := dna.ReverseLookup(ip.String())
		if err != nil {
			continue
		}
		for _, d := range domains {
			// Filter out keywords specific to target - Needed to avoid enumerating all third-party services using public cloud load balancers
			hasSub := func(allowed []string, domain string) bool {
				for i := range allowed {
					if strings.Contains(domain, allowed[i]) {
						return true
					}
				}
				return false
			}
			isTracked := false
			if !hasSub(allowed, d) {
				break
			}
			if rep.SliceContainsString(assess.Domains, d) {
				isTracked = true
			}

			if isTracked {
				break
			}
			if len(assess.UntrackedDomains) == 0 {
				// Duplicated code
				inner := map[string][]string{d: {ip.String()}}
				assess.UntrackedDomains = append(assess.UntrackedDomains, inner)
			} else {
				for _, ut := range assess.UntrackedDomains {
					utDomains := ut[d]
					if _, exists := ut[d]; !exists {
						// Duplicated code
						inner := map[string][]string{d: {ip.String()}}
						assess.UntrackedDomains = append(assess.UntrackedDomains, inner)
					} else {
						if !rep.SliceContainsString(utDomains, ip.String()) {
							utDomains = append(utDomains, ip.String())
						}
					}

				}
			}
		}
	}
}

func domainIPLookups() {
	for i := range assess.Domains {
		var ut models.UntrackedIP
		ut.Domain = assess.Domains[i]
		ips, err := dna.IPLookup(assess.Domains[i])
		if err != nil {
			break
		}
		for ip := range ips {
			if !ipa.IPExistsIn(ips[ip], &assess.IPAddresses) && ips[ip] != nil {
				var ipc models.IPCollection
				ipa.NoCheckAddIPtoAddresses(ips[ip], &ipc)
				if ipa.IsIPv4(ips[ip]) {
					ut.Addresses.IPv4 = append(ut.Addresses.IPv4, ips[ip])
				} else {
					ut.Addresses.IPv6 = append(ut.Addresses.IPv6, ips[ip])
				}
			} else {
				ipa.NoCheckAddIPtoAddresses(ips[ip], &assess.IPAddresses)
			}
		}
		if len(ut.Addresses.IPv4) > 0 || len(ut.Addresses.IPv6) > 0 {
			assess.UntrackedIPAddresses = append(assess.UntrackedIPAddresses, ut)
		}
	}

}

func reviewPrivateIPs() {
	tracked := append(assess.IPAddresses.IPv4, assess.IPAddresses.IPv6...)
	var untracked []net.IP
	for _, ut := range assess.UntrackedIPAddresses {
		untracked = append(untracked, ut.Addresses.IPv4...)
		untracked = append(untracked, ut.Addresses.IPv6...)
	}
	allIps := append(tracked, untracked...)
	tracked, tracked = nil, nil
	for i := range allIps {
		if allIps[i].IsPrivate() {
			ipa.NoCheckAddIPtoAddresses(allIps[i], &assess.PrivateIPAddresses)
		}
	}
}

func printURLTargets() {
	fmt.Println("\n---- Potential Domains ----")
	targets := make([]string, len(assess.Domains))

	// Print web targets
	for i := range assess.Domains {
		targets[i] = assess.Domains[i]
	}
	for _, alias := range assess.Aliases {
		for _, al := range alias.Relationship {
			for key, _ := range al {
				if !rep.SliceContainsString(targets, al[key]) {
					targets = append(targets, al[key])
				}
			}
		}
	}
	for i := range targets {
		fmt.Println(targets[i] + "/")
	}
}

func printUntrackedIPs() {
	fmt.Println("\n---- Untracked IPs ----")
	// More mem efficient with a loop instead of append?
	ips := make([]net.IP, 0)
	for _, ip := range assess.UntrackedIPAddresses {
		ips = append(ips, ip.Addresses.IPv4...)
	}
	for _, utIps := range assess.UntrackedIPAddresses {
		var comb []net.IP
		comb = append(comb, utIps.Addresses.IPv4...)
		comb = append(comb, utIps.Addresses.IPv6...)
		for _, ip := range comb {
			who, err := dna.Whois(ip.String())
			if err != nil || strings.Contains(who, "Error: Invalid query") {
				who = "Unknown WHOIS"
			} else {
				parsedWhois := dna.ParseWHOIS(who)
				who = parsedWhois.OrgName
			}
			fmt.Printf("%s - %s - %s\n", ip.String(), utIps.Domain, who)
		}
	}
}

func printDNSSECMissing() {
	fmt.Println("\n---- No DNSSEC ----")
	for _, dom := range assess.MissingDNSSEC {
		fmt.Println(dom)
	}
}
