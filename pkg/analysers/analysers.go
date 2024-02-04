package analysers

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/url"
	"strings"
)

type Analyser struct{}

var resolverIP = "8.8.8.8"

func (an *Analyser) ReverseLookup(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (an *Analyser) IPLookup(domain string) ([]net.IP, error) {
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

func (an *Analyser) GetCNAME(u string) (string, error) {
	u, err := checkForURLScheme(u)
	if err != nil {
		return "", err
	}

	hostname, err := extractHostname(u)
	if err != nil {
		return "", err
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	// Ensure the hostname is fully qualified
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, resolverIP+":53")
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

func (an *Analyser) GetTXT(u string) ([]string, error) {
	hostname, err := checkForURLScheme(u)
	if err != nil {
		return nil, err
	}
	hostname, err = extractHostname(hostname)
	if err != nil {
		return nil, err
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	// Ensure the hostname is fully qualified
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
	m.RecursionDesired = true

	// Perform the DNS query using the specified resolver
	r, _, err := c.Exchange(m, resolverIP+":53")
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	var txtRecords []string
	for _, ans := range r.Answer {
		if t, ok := ans.(*dns.TXT); ok {
			for _, txt := range t.Txt {
				txtRecords = append(txtRecords, txt)
			}
		}
	}

	return txtRecords, nil
}

func checkForURLScheme(u string) (string, error) {
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
