package dns_analysers

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"log"
	"net"
	"orbit/models"
	"regexp"
	"strings"
)

type DNSAnalyser struct{}

var resolverIP = "8.8.8.8"

func (an *DNSAnalyser) Whois(target string) (string, error) {
	if target == "" {
		return "", errors.New("empty string for whois request")
	}
	result, err := whois.Whois(target)
	if err != nil {
		return "", err
	}
	return result, nil
}

// GetAllRecords queries for specific DNS record types for a domain.
func (an *DNSAnalyser) GetAllRecords(domain string) ([][]dns.RR, error) {
	client := new(dns.Client)
	var results [][]dns.RR
	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeCNAME, dns.TypeNS, dns.TypeSRV}

	for _, recordType := range recordTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), recordType)
		m.RecursionDesired = true

		r, _, err := client.Exchange(m, resolverIP+":53")
		if err != nil {
			log.Printf("Error querying %s records: %v\n", dns.TypeToString[recordType], err)
			break
		}
		if r.Answer != nil {
			results = append(results, r.Answer)
		}
	}
	return results, nil
}

// ReverseLookup performs a reverse lookup of domains associated with an IP address.
func (an *DNSAnalyser) ReverseLookup(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	for i := range names {
		if strings.HasSuffix(names[i], ".") {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
	}
	if err != nil {
		return nil, err
	}
	return names, nil
}

// IPLookup returns IP addresses associated with a domain.
func (an *DNSAnalyser) IPLookup(domain string) ([]net.IP, error) {
	var res []net.IP
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		res = append(res, ip)
	}
	return res, nil
}

// GetCNAME gets CNAME records for a domain.
func (an *DNSAnalyser) GetCNAME(domain string) (string, error) {
	hostname, err := normaliseAndExtractHostname(domain)
	if err != nil {
		return "", err
	}

	r, err := initDNSMsg(domain, dns.TypeCNAME)
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	if len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				return cname.Target, nil
			}
		}
	}

	return "", fmt.Errorf("no CNAME record found for %s", hostname)
}

// GetTXT gets TXT records for a domain.
func (an *DNSAnalyser) GetTXT(domain string) ([]string, error) {
	hostname, err := normaliseAndExtractHostname(domain)
	if err != nil {
		return nil, err
	}

	// Perform the DNS query using the specified resolver
	msg, err := initDNSMsg(hostname, dns.TypeTXT)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	var txtRecords []string
	for _, ans := range msg.Answer {
		if t, ok := ans.(*dns.TXT); ok {
			for _, txt := range t.Txt {
				txtRecords = append(txtRecords, txt)
			}
		}
	}
	return txtRecords, nil
}

// DNSSECEnabled returns a boolean based on whether DNSSEC is enabled on a domain.
func (an *DNSAnalyser) DNSSECEnabled(domain string) (bool, error) {
	if strings.HasSuffix(domain, ".") {
		domain = strings.TrimSuffix(domain, ".")
	}
	msg, err := initDNSMsg(domain, dns.TypeDS)
	if err != nil {
		return false, err
	}

	for _, ans := range msg.Answer {
		if _, ok := ans.(*dns.DS); ok {
			return true, nil
		}
	}
	return false, nil
}

func (an *DNSAnalyser) ParseWHOIS(input string) *models.WHOISRecord {
	scanner := bufio.NewScanner(strings.NewReader(input))
	record := models.WHOISRecord{}

	// Define regular expressions for the fields of interest
	regexMap := map[string]*regexp.Regexp{
		"NetRange":      regexp.MustCompile(`(?i)^NetRange:\s+(.+)`),
		"CIDR":          regexp.MustCompile(`(?i)^CIDR:\s+(.+)`),
		"NetName":       regexp.MustCompile(`(?i)^NetName:\s+(.+)`),
		"Organization":  regexp.MustCompile(`(?i)^Organization:\s+(.+)`),
		"OrgName":       regexp.MustCompile(`(?i)^OrgName:\s+(.+)`),
		"Address":       regexp.MustCompile(`(?i)^Address:\s+(.+)`),
		"City":          regexp.MustCompile(`(?i)^City:\s+(.+)`),
		"StateProv":     regexp.MustCompile(`(?i)^StateProv:\s+(.+)`),
		"PostalCode":    regexp.MustCompile(`(?i)^PostalCode:\s+(.+)`),
		"Country":       regexp.MustCompile(`(?i)^Country:\s+(.+)`),
		"OrgTechEmail":  regexp.MustCompile(`(?i)^OrgTechEmail:\s+(.+)`),
		"OrgAbuseEmail": regexp.MustCompile(`(?i)^OrgAbuseEmail:\s+(.+)`),
		"Remarks":       regexp.MustCompile(`(?i)^remarks:\s+(.+)`),
	}

	for scanner.Scan() {
		line := scanner.Text()
		for field, regex := range regexMap {
			matches := regex.FindStringSubmatch(line)
			if len(matches) > 1 {
				// Using reflection to set the value dynamically based on the field
				// This simplifies the addition of new fields
				switch field {
				case "NetRange":
					record.NetRange = matches[1]
				case "CIDR":
					record.CIDR = matches[1]
				case "NetName":
					record.NetName = matches[1]
				case "Organization":
					record.Organization = matches[1]
				case "OrgName":
					record.OrgName = matches[1]
				case "Address":
					// Concatenate addresses if more than one
					if record.Address != "" {
						record.Address += "; " + matches[1]
					} else {
						record.Address = matches[1]
					}
				case "City":
					record.City = matches[1]
				case "StateProv":
					record.StateProv = matches[1]
				case "PostalCode":
					record.PostalCode = matches[1]
				case "Country":
					record.Country = matches[1]
				case "OrgTechEmail":
					record.OrgTechEmail = matches[1]
				case "OrgAbuseEmail":
					record.OrgAbuseEmail = matches[1]
				case "Remarks":
					if strings.Contains(matches[1], "@") {
						record.Remarks = strings.Split(matches[1], "@")[1]
					}
				}
			}
		}
	}

	return &record
}

func initDNSMsg(domain string, dnsType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	c := new(dns.Client)
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.RecursionDesired = true

	msg, _, err := c.Exchange(m, resolverIP+":53")
	if err != nil {
		return msg, err
	}
	return msg, nil
}
