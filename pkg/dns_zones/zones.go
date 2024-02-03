package dns_zones

import (
	"errors"
	"fmt"
	"orbit/internal"
	"os"
	"strconv"
	"strings"
)

type DNSZones struct {
	zoneFile ZoneFile
}

func (dz *DNSZones) GetZoneData(path string) ([]ZoneFile, error) {
	var zf []ZoneFile
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	switch mode := fileInfo.Mode(); {
	case mode.IsDir():
		fmt.Printf("Its a directory")
	case mode.IsRegular():
		fb, err := internal.ReadFileLines(path)
		if err != nil {
			return nil, err
		}
		if len(fb) == 0 {
			return nil, errors.New("empty file")
		}
		fd, err := parseZoneFileData(fb)
		if err != nil {
			return nil, err
		}
		zf = append(zf, fd)
	default:
		return nil, errors.New("invalid zone file case")
	}

	return zf, nil
}

func parseZoneFileData(data []string) (ZoneFile, error) {
	var zf ZoneFile

	zf.Origin = strings.Split(data[0], " ")[1]
	i := 0
	for _, l := range data {
		var zr DNSRecord
		l = cleanTabsAndSpaces(l)
		sections := strings.Split(l, " ")
		if i > 0 {
			zr.Name = sections[0]
			ttl, err := strconv.Atoi(sections[1])
			if err != nil {
				return ZoneFile{}, err
			}
			zr.TTL = ttl
			zr.Class = sections[2]
			zr.Type = sections[3]
			con := sections[4]
			if !strings.Contains(con, " ") {
				zr.Content = con
			} else {
				zr.Content = parseRecordContentField(sections)
			}
		}
		i++
		zf.Records = append(zf.Records, zr)
	}
	return zf, nil
}

func parseRecordContentField(record []string) string {
	var res []string
	for i := range record {
		if i > 5 {
			res = append(res, record[i])
		}
	}
	return strings.Join(res, " ")
}

func cleanTabsAndSpaces(record string) string {
	runes := []rune(record)
	var sb strings.Builder
	var last rune
	for _, r := range runes {
		if r == '\t' {
			r = ' '
		}
		if r == ' ' && last == r {
			continue
		}
		last = r
		sb.WriteString(string(r))
	}
	return sb.String()
}
