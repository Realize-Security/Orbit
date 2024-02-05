package dns_analysers

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/url"
	"strings"
)

type DNSAnalyser struct{}

var resolverIP = "8.8.8.8"

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
			continue
		}

		results = append(results, r.Answer)
	}
	return results, nil
}

// ReverseLookup performs a reverse lookup of domains associated with an IP address.
func (an *DNSAnalyser) ReverseLookup(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
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

func normaliseAndExtractHostname(domain string) (string, error) {
	domain, err := normaliseURLScheme(domain)
	if err != nil {
		return "", err
	}

	domain, err = extractHostname(domain)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// normaliseURLScheme takes URLs without a schema or path and prepends a schema and '/' respectively.
// I.e., 'www.realizesec.com' becomes 'https:///www.realizesec.com/'
func normaliseURLScheme(u string) (string, error) {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if len(parsedUrl.Scheme) == 0 {
		u = "https://" + u
	}
	if !strings.HasSuffix(u, "/") {
		u = u + "/"
	}
	return u, nil
}

func extractHostname(urlStr string) (string, error) {
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}
