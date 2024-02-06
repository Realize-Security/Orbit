package ip_addresses

import (
	"net"
	"orbit/models"
)

type IPAddresses struct{}

func (ipa *IPAddresses) IPAddressesFromFile(path string) {}

// IPAddressesFromZones extract IP addresses from zone file data.
func (ipa *IPAddresses) IPAddressesFromZones(zone models.ZoneFile) *models.IPCollection {
	var results models.IPCollection
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
		if ipa.IsIPv4(ip) && !exists(results.IPv4, ip) {
			results.IPv4 = append(results.IPv4, ip)
		} else if ipa.IsIPv6(ip) && !exists(results.IPv4, ip) {
			results.IPv6 = append(results.IPv6, ip)
		}
	}
	return &results
}

// AddIPtoAddresses receives an IP address and validates if IPv4 or 6 and assigns to ASMAssessment.IPAddresses
func (ipa *IPAddresses) AddIPtoAddresses(ip net.IP, asm *models.ASMAssessment) {
	if ipa.IsIPv4(ip) {
		asm.IPAddresses.IPv4 = append(asm.IPAddresses.IPv4, ip)
	} else {
		asm.IPAddresses.IPv6 = append(asm.IPAddresses.IPv6, ip)
	}
}

func (ipa *IPAddresses) IPExistsIn(ip net.IP, asm *models.ASMAssessment) bool {
	for i := range asm.IPAddresses.IPv4 {
		if asm.IPAddresses.IPv4[i].Equal(ip) {
			return true
		}
	}
	for i := range asm.IPAddresses.IPv6 {
		if asm.IPAddresses.IPv6[i].Equal(ip) {
			return true
		}
	}
	return false
}

// IsIPv4 returns true if the value is a valid IPv4.
func (ipa *IPAddresses) IsIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil
}

// IsIPv6 returns true if the value is a valid IPv6.
func (ipa *IPAddresses) IsIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}
