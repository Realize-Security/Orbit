package reporting

import (
	"orbit/models"
	"strings"
)

type Reporting struct{}

// AandAAARecords prints A and AAA records to the terminal grouped by zone.
func (rep *Reporting) AandAAARecords(zone models.ZoneFile) []string {
	return rep.getRecords(zone, []string{"A", "AAA"})
}

// CNAMERecords prints CNAME records to the terminal grouped by zone.
func (rep *Reporting) CNAMERecords(zone models.ZoneFile) []string {
	return rep.getRecords(zone, []string{"CNAME"})
}

// GetFQDNTargets prints potential targets by outputting A/AAA/CNAME values and IP addresses.
func (rep *Reporting) GetFQDNTargets(zone models.ZoneFile) []string {
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

// getRecords prints requested records to the terminal grouped by zone.
func (rep *Reporting) getRecords(zone models.ZoneFile, rec []string) []string {
	var result []string
	records := rep.sortRecords(&zone, rec)
	for _, r := range records {
		result = append(result, r)
	}
	return result
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
func (rep *Reporting) sortRecords(d *models.ZoneFile, requested []string) []string {
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
