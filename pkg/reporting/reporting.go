package reporting

import (
	"fmt"
	"net"
	"orbit/pkg/dns_zones"
	"strings"
)

type Reporting struct{}

// ListAandAAARecords prints A and AAA records to the terminal grouped by zone.
func (rep *Reporting) ListAandAAARecords(zone dns_zones.ZoneFile) {
	rep.listSingleRecord(zone, []string{"A", "AAA"})
}

// ListCNAMERecords prints CNAME records to the terminal grouped by zone.
func (rep *Reporting) ListCNAMERecords(zone dns_zones.ZoneFile) {
	rep.listSingleRecord(zone, []string{"CNAME"})
}

// listSingleRecord prints requested records to the terminal grouped by zone.
func (rep *Reporting) listSingleRecord(zone dns_zones.ZoneFile, rec []string) {
	noResults := true
	records := rep.sortRecords(&zone, rec)
	noResults = false
	fmt.Printf("---- %s ----\n", zone.Origin)
	for _, r := range records {
		fmt.Println(r)
	}
	if noResults {
		fmt.Println("[!] No records found.")
	}
}

// GetFQDNTargets prints potential targets by outputting A/AAA/CNAME values and IP addresses.
func (rep *Reporting) GetFQDNTargets(zone dns_zones.ZoneFile) []string {
	var results []string
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
	return results
}

// GetIPAddressTargets extract IP addresses
func (rep *Reporting) GetIPAddressTargets(zone dns_zones.ZoneFile) *dns_zones.IPCollection {
	var results dns_zones.IPCollection
	for _, rec := range zone.Records {
		ip := net.ParseIP(rec.Content)
		exists := func(ips []net.IP, ip net.IP) bool {
			for i := range ips {
				if ips[i].String() == ip.String() {
					return true
				}
			}
			return false
		}
		if rep.isIPv4(ip) && !exists(results.IPv4, ip) {
			results.IPv4 = append(results.IPv4, ip)
		} else if rep.isIPv6(ip) && !exists(results.IPv4, ip) {
			results.IPv6 = append(results.IPv6, ip)
		}
	}
	return &results
}

func (rep *Reporting) isIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil
}

func (rep *Reporting) isIPv6(ip net.IP) bool {
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
