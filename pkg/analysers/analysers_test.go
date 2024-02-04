package analysers

import (
	"testing"
)

var (
	cnameDomain = "autodiscover.outlook.com"
	domainShort = "realizesec.com"
	ipAddress   = "8.8.8.8"
)

func TestReverseLookup(t *testing.T) {
	an := &Analyser{}
	_, err := an.ReverseLookup(ipAddress)
	if err != nil {
		t.Errorf("ReverseLookup failed: %v", err)
	}
}

func TestIPLookup(t *testing.T) {
	an := &Analyser{}
	_, err := an.IPLookup(domainShort)
	if err != nil {
		t.Errorf("IPLookup failed: %v", err)
	}
}

func TestGetCNAME(t *testing.T) {
	an := &Analyser{}
	_, err := an.GetCNAME(cnameDomain)
	if err != nil {
		t.Errorf("GetCNAME failed: %v", err)
	}
}

func TestGetTXT(t *testing.T) {
	an := &Analyser{}
	_, err := an.GetTXT(domainShort)
	if err != nil {
		t.Errorf("GetTXT failed: %v", err)
	}
}
