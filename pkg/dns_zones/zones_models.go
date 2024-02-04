package dns_zones

import "net"

type ZoneFile struct {
	Origin  string
	Records []DNSRecord
}

type DNSRecord struct {
	Type    string
	Class   string
	Name    string
	Content string
	TTL     int
}

type IPCollection struct {
	IPv4 []net.IP
	IPv6 []net.IP
}
