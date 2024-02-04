package dns_zones

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
	IPv4 []string
	IPv6 []string
}
