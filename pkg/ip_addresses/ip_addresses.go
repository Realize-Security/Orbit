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

// AddManyIPStrAddresses receives an IP address and validates if IPv4 or 6 and assigns to ASMAssessment.IPAddresses
func (ipa *IPAddresses) AddManyIPStrAddresses(ips []string, ipc *models.IPCollection) {
	for i := range ips {
		if ip := net.ParseIP(ips[i]); ip != nil {
			ipa.CheckAddIPtoAddresses(ip, ipc)
		}
	}
}

// AddManyIPAddresses receives an IP address and validates if IPv4 or 6 and assigns to ASMAssessment.IPAddresses
func (ipa *IPAddresses) AddManyIPAddresses(ips []net.IP, ipc *models.IPCollection) {
	for i := range ips {
		ipa.CheckAddIPtoAddresses(ips[i], ipc)
	}
}

// CheckAddIPtoAddresses receives an IP address and validates if IPv4 or 6 and assigns to ASMAssessment.IPAddresses.
// Does not ad the IP if it already exists.
func (ipa *IPAddresses) CheckAddIPtoAddresses(ip net.IP, ipc *models.IPCollection) {
	if ipa.IPExistsIn(ip, ipc) {
		return
	}
	ipa.addIPInternal(ip, ipc)
}

// NoCheckAddIPtoAddresses receives an IP address and validates if IPv4 or 6 and assigns to ASMAssessment.IPAddresses
// Does NOT check if IP already exists.
func (ipa *IPAddresses) NoCheckAddIPtoAddresses(ip net.IP, ipc *models.IPCollection) {
	ipa.addIPInternal(ip, ipc)
}

func (ipa *IPAddresses) addIPInternal(ip net.IP, ipc *models.IPCollection) {
	if ipa.IsIPv4(ip) {
		ipc.IPv4 = append(ipc.IPv4, ip)
	} else {
		ipc.IPv6 = append(ipc.IPv6, ip)
	}
}

func (ipa *IPAddresses) IPExistsIn(ip net.IP, ipc *models.IPCollection) bool {
	for i := range ipc.IPv4 {
		if ipc.IPv4[i].Equal(ip) {
			return true
		}
	}
	for i := range ipc.IPv6 {
		if ipc.IPv6[i].Equal(ip) {
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
