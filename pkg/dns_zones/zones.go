package dns_zones

import (
	"errors"
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
		records, err := readZoneFileDirectory(path)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			return nil, errors.New("no zone files found in directory: " + path)
		}
		zf = records
	case mode.IsRegular():
		fb, err := internal.ReadFileLines(path)
		if err != nil {
			return nil, err
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

func readZoneFileDirectory(path string) ([]ZoneFile, error) {
	var results []ZoneFile
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	zoneFiles := make([]os.DirEntry, 0)
	for _, file := range files {
		if internal.IsZoneFile(file) {
			zoneFiles = append(zoneFiles, file)
		}
		for i := range zoneFiles {
			zfLines, err := internal.ReadFileLines(path + "/" + zoneFiles[i].Name())
			if err != nil {
				continue
			}
			zfData, err := parseZoneFileData(zfLines)
			if err != nil {
				continue
			}
			results = append(results, zfData)
		}
	}
	return results, err
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
			zf.Records = append(zf.Records, zr)
		}
		i++
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
