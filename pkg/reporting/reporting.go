package reporting

import (
	"fmt"
	"net"
	"orbit/pkg/dns_zones"
	"strings"
)

var (
	ipv4 = "ipv4"
	ipv6 = "ipv6"
)

type Reporting struct{}

// ListAandAAARecords prints A and AAA records to the terminal grouped by zone.
func (rep *Reporting) ListAandAAARecords(data []dns_zones.ZoneFile) {
	rep.listRecords(data, []string{"A", "AAA"})
}

// ListCNames prints CNAME records to the terminal grouped by zone.
func (rep *Reporting) ListCNames(data []dns_zones.ZoneFile) {
	rep.listRecords(data, []string{"CNAME"})
}

// listRecords prints requested records to the terminal grouped by zone.
func (rep *Reporting) listRecords(data []dns_zones.ZoneFile, rec []string) {
	noResults := true
	for _, d := range data {
		records := rep.sortRecords(&d, rec)
		if len(records) == 0 {
			continue
		}
		noResults = false
		fmt.Printf("---- %s ----\n", d.Origin)
		for _, r := range records {
			fmt.Println(r)
		}
	}
	if noResults {
		fmt.Println("[!] No records found.")
	}
}

// GetFQDNTargets prints potential targets by outputting A/AAA/CNAME values and IP addresses.
func (rep *Reporting) GetFQDNTargets(data []dns_zones.ZoneFile) []string {
	var results []string
	for _, zone := range data {
		origin := strings.TrimSuffix(zone.Origin, ".")
		for _, rec := range zone.Records {
			if rec.Type == "A" || rec.Type == "AAA" || rec.Type == "CNAME" {
				fqdn := rec.Name + "." + origin
				if rec.Name == "@" || rec.Name == "*" {
					fqdn = origin
				}
				if !rep.contains(results, fqdn) {
					results = append(results, fqdn)
				}
			}
		}
	}
	return results
}

// GetIPAddressTargets extract IP addresses
func (rep *Reporting) GetIPAddressTargets(data []dns_zones.ZoneFile) *dns_zones.IPCollection {
	var results dns_zones.IPCollection
	for _, zone := range data {
		for _, rec := range zone.Records {
			ip := rec.Content
			if rep.isIPv4(ip) && !rep.contains(results.IPv4, ip) {
				results.IPv4 = append(results.IPv4, ip)
			} else if rep.isIPv6(ip) && !rep.contains(results.IPv6, ip) {
				results.IPv6 = append(results.IPv6, ip)
			}
		}
	}
	return &results
}

func (rep *Reporting) isIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func (rep *Reporting) isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// contains checks if a []string contains a substring.
func (rep *Reporting) contains(items []string, str string) bool {
	for i := range items {
		if items[i] == str {
			return true
		}
	}
	return false
}

// sortRecords returns a []string of records for the requested types.
func (rep *Reporting) sortRecords(d *dns_zones.ZoneFile, requested []string) []string {
	var temp []string
	for _, rec := range d.Records {
		for _, req := range requested {
			if rec.Type == req {
				temp = append(temp, rec.Name+" - "+rec.Content)
			}
		}
	}
	return temp
}
