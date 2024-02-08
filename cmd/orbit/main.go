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
	"strings"
)

var (
	zones = zone_files.DNSZones{}
	ipa   = ip_addresses.IPAddresses{}
	rep   = reporting.Reporting{}
	dna   = dns_analysers.DNSAnalyser{}
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Println("[!] Failed to parse initialise arguments: ", err.Error())
		log.Print("[!] Exiting...")
		os.Exit(1)
	}

	var assess = models.ASMAssessment{}

	zf, _ := cmd.RootCmd.PersistentFlags().GetString("iZ")
	if zf != "" {
		zfResults, err := zones.GetZoneData(zf)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		assess.Zones = zfResults
	}

	ips, _ := cmd.RootCmd.PersistentFlags().GetString("iI")
	if ips != "" {
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

	urlList, _ := cmd.RootCmd.PersistentFlags().GetString("iU")
	if urlList != "" {
		existingUrls, err := file_management.ReadFileLines(urlList)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for i := range existingUrls {
			assess.Domains = append(assess.Domains, existingUrls[i])
		}
	}

	// Get IP addresses from A/AAA records
	for i := range assess.Zones {
		aRecs := rep.AandAAARecords(&assess.Zones[i])
		ipa.AddManyIPStrAddresses(aRecs, &assess.IPAddresses)
	}

	// Get aliases
	for _, zone := range assess.Zones {
		aliases := rep.CNAMERecords(&zone)
		if aliases != nil && len(aliases) > 0 {
			al := models.AliasRecords{
				Domain:       zone.Origin,
				Relationship: aliases,
			}
			assess.Aliases = append(assess.Aliases, al)
		}

		o := zone.Origin
		// Check for DNSSEC enablement
		if res, _ := dna.DNSSECEnabled(o); res {
			rep.AddMissingDNSSec(o, &assess)
		}
		ip := net.ParseIP(o)
		if ip != nil {
			if !ipa.IPExistsIn(ip, &assess.IPAddresses) {
				ipa.CheckAddIPtoAddresses(ip, &assess.IPAddresses)
			}
		} else {
			targets := rep.GetFQDNs(&zone)
			for i := range targets {
				rep.AddURLToAsmDomainsDupSafe(targets[i], &assess)
			}
		}
	}

	// Sanity check A/AAA against domains
	//for _, zone := range assess.Zones {
	//	res, _ := dna.GetCNAME(zone.Origin)
	//	fmt.Println(res)
	//}

	// Reverse lookups
	for _, ip := range assess.IPAddresses.IPv4 {
		domains, err := dna.ReverseLookup(ip.String())
		if err != nil {
			continue
		}
		for _, d := range domains {
			// Filter out keywords specific to target - Needed to avoid enumerating all third-party services using public cloud load balancers
			allowed := []string{"money", "fx", "ttt", "novo", "explore", "currency"}
			hasSub := func(allowed []string, domain string) bool {
				for i := range allowed {
					if strings.Contains(domain, allowed[i]) {
						return true
					}
				}
				return false
			}
			if hasSub(allowed, d) {

				isTracked := false

				for i := range assess.Domains {
					if d == assess.Domains[i] {
						isTracked = true
						break
					}
				}

				if !isTracked {
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
	}

	// Lookup IPs of all known domains and track otherwise unknown IPs
	for i := range assess.Domains {
		ips, err := dna.IPLookup(assess.Domains[i])
		if err != nil {
			break
		}
		for ip := range ips {
			if !ipa.IPExistsIn(ips[ip], &assess.IPAddresses) {
				ipa.NoCheckAddIPtoAddresses(ips[ip], &assess.UntrackedIPAddresses)
			} else {
				ipa.NoCheckAddIPtoAddresses(ips[ip], &assess.IPAddresses)
			}
		}
	}

	// Review all IP addresses and note any exposed internal IP addresses in records.
	tracked := append(assess.IPAddresses.IPv4, assess.IPAddresses.IPv6...)
	untracked := append(assess.UntrackedIPAddresses.IPv4, assess.UntrackedIPAddresses.IPv6...)
	allIps := append(tracked, untracked...)
	tracked, tracked = nil, nil
	for i := range allIps {
		if allIps[i].IsPrivate() {
			ipa.NoCheckAddIPtoAddresses(allIps[i], &assess.PrivateIPAddresses)
		}
	}

	// Print web targets
	for _, dom := range assess.Domains {
		fmt.Println(dom)
	}
	for _, alias := range assess.Aliases {
		for _, al := range alias.Relationship {
			for key, _ := range al {
				fmt.Println(al[key])
			}
		}
	}
}
