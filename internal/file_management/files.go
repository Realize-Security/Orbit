package file_management

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
)

func ReadFileBytes(path string) ([]byte, error) {
	var bytes []byte
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %s", err)
		}
	}(file)

	bytes, err = io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func ReadFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("unable to open file")
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("error closing file: %s", file.Name())
		}
	}(file)

	res := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		res = append(res, scanner.Text())
	}

	return res, nil
}

func IsZoneFile(file os.DirEntry) bool {
	if !file.IsDir() && filepath.Ext(file.Name()) == ".zone" {
		return true
	}
	return false
}
