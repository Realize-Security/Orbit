package reporting

import (
	"orbit/models"
	"strings"
)

type Reporting struct{}

// AandAAARecords prints A and AAA records to the terminal grouped by zone.
func (rep *Reporting) AandAAARecords(zone *models.ZoneFile) []string {
	return rep.sortRecords(zone, []string{"A", "AAA"})
}

// CNAMERecords prints CNAME records to the terminal grouped by zone.
func (rep *Reporting) CNAMERecords(zone *models.ZoneFile) []map[string]string {
	var results []map[string]string
	for _, rec := range zone.Records {
		if rec.Type == "CNAME" {
			innerMap := make(map[string]string)
			innerMap[rec.Name+"."+zone.Origin] = rec.Content
			results = append(results, innerMap)
		}
	}
	return results
}

// GetFQDNTargets prints potential targets by outputting A/AAA/CNAME values and IP addresses.
func (rep *Reporting) GetFQDNTargets(zone *models.ZoneFile) []string {
	var results []string
	origin := strings.TrimSuffix(zone.Origin, ".")
	for _, rec := range zone.Records {
		if rec.Type == "A" || rec.Type == "AAA" || rec.Type == "CNAME" {
			fqdn := rec.Name + "." + origin
			if rec.Name == "@" || rec.Name == "*" {
				fqdn = origin
			}
			if !rep.SliceContainsString(results, fqdn) {
				results = append(results, fqdn)
			}
		}
	}
	return results
}

// AddURLToAsmDomainsDupSafe checks if the domains list already contains a URL and adds it if not.
func (rep *Reporting) AddURLToAsmDomainsDupSafe(url string, asm *models.ASMAssessment) {
	if !rep.SliceContainsString(asm.Domains, url) {
		asm.Domains = append(asm.Domains, url)
	}
}

// AddURLToUntrackedDomainsDupSafe checks if the domains list already contains a URL and adds it if not.
func (rep *Reporting) AddURLToUntrackedDomainsDupSafe(url string, ips []string, asm *models.ASMAssessment) {
	for _, domain := range asm.UntrackedDomains {
		if _, exists := domain[url]; exists {
			domain[url] = append(domain[url], ips...)
			domain[url] = rep.deduplicateStrSlice(domain[url])
		} else {
			domain[url] = ips
		}
	}
}

func (rep *Reporting) AddMissingDNSSec(domain string, asm *models.ASMAssessment) {
	if !rep.SliceContainsString(asm.MissingDNSSEC, domain) {
		asm.MissingDNSSEC = append(asm.MissingDNSSEC, domain)
	}
}

// SliceContainsString checks if a []string SliceContainsString a substring.
func (rep *Reporting) SliceContainsString(items []string, str string) bool {
	for i := range items {
		if items[i] == str {
			return true
		}
	}
	return false
}

// sortRecords returns a []string of records for the requested types.
func (rep *Reporting) sortRecords(d *models.ZoneFile, requested []string) []string {
	var temp []string
	for _, rec := range d.Records {
		for _, req := range requested {
			if rec.Type == req {
				temp = append(temp, rec.Content)
			}
		}
	}
	return temp
}

// deduplicateStrSlice returns a new slice without duplicated values.
func (rep *Reporting) deduplicateStrSlice(sl []string) []string {
	var res []string
	for _, s := range sl {
		if rep.SliceContainsString(res, s) {
			res = append(res, s)
		}
	}
	return res
}
