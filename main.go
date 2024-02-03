package main

import (
	"fmt"
	"orbit/pkg/dns_zones"
	"os"
)

func main() {
	zones := dns_zones.DNSZones{}
	results, err := zones.GetZoneData("/Users/richard/operations/moneycorp/attack_surface_mapping/test_data/Zone Files/moneycorp.tech.zone")
	if err != nil {
		os.Exit(1)
	}
	for _, result := range results {
		fmt.Println(result.Origin)
		for _, res := range result.Records {
			fmt.Println(res.Content)
		}
	}
}
