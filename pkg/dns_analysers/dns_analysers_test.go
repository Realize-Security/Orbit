package dns_analysers

import (
	"testing"
)

var (
	cnameDomain = "autodiscover.outlook.com"
	domainShort = "realizesec.com"
	ipAddress   = "8.8.8.8"
)

func TestGetAllRecords(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.GetAllRecords(domainShort)
	if err != nil {
		t.Errorf("Failed to lookup records for %v", err)
	}
}

func TestReverseLookup(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.ReverseLookup(ipAddress)
	if err != nil {
		t.Errorf("ReverseLookup failed: %v", err)
	}
}

func TestIPLookup(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.IPLookup(domainShort)
	if err != nil {
		t.Errorf("IPLookup failed: %v", err)
	}
}

func TestGetCNAME(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.GetCNAME(cnameDomain)
	if err != nil {
		t.Errorf("GetCNAME failed: %v", err)
	}
}

func TestGetTXT(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.GetTXT(domainShort)
	if err != nil {
		t.Errorf("GetTXT failed: %v", err)
	}
}

func TestDNSSECEnabled(t *testing.T) {
	an := &DNSAnalyser{}
	_, err := an.DNSSECEnabled(domainShort)
	if err != nil {
		t.Errorf("Checking DNSSEC failed: %v", err)
	}
}
