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
			if !rep.sliceContainsString(results, fqdn) {
				results = append(results, fqdn)
			}
		}
	}
	return results
}

// AddURLToAsmDomains checks if the domains list already contains a URL and adds it if not.
func (rep *Reporting) AddURLToAsmDomains(url string, asm *models.ASMAssessment) {
	if !rep.sliceContainsString(asm.Domains, url) {
		asm.Domains = append(asm.Domains, url)
	}
}

func (rep *Reporting) AddMissingDNSSec(domain string, asm *models.ASMAssessment) {
	if !rep.sliceContainsString(asm.MissingDNSSEC, domain) {
		asm.MissingDNSSEC = append(asm.MissingDNSSEC, domain)
	}
}

// sliceContainsString checks if a []string sliceContainsString a substring.
func (rep *Reporting) sliceContainsString(items []string, str string) bool {
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
