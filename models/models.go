package models

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

type ASMAssessment struct {
	Zones                []ZoneFile
	IPAddresses          IPCollection
	UntrackedIPAddresses []UntrackedIP
	PrivateIPAddresses   IPCollection
	Domains              []string
	UntrackedDomains     []map[string][]string
	MissingDNSSEC        []string
	Aliases              []AliasRecords
	HostingProviders     map[string][]string
}

type UntrackedIP struct {
	Domain    string
	Addresses IPCollection
}

type AliasRecords struct {
	Domain       string
	Relationship []map[string]string
}

type WHOISRecord struct {
	NetRange      string
	CIDR          string
	NetName       string
	Organization  string
	OrgName       string
	Address       string
	City          string
	StateProv     string
	PostalCode    string
	Country       string
	OrgTechEmail  string
	OrgAbuseEmail string
	Remarks       string
}
