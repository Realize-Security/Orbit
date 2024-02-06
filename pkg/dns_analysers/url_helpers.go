package dns_analysers

import (
	"github.com/go-playground/validator/v10"
	"net/url"
	"strings"
)

func normaliseAndExtractHostname(domain string) (string, error) {
	domain, err := normaliseURLScheme(domain)
	if err != nil {
		return "", err
	}

	domain, err = extractHostname(domain)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// normaliseURLScheme takes URLs without a schema or path and prepends a schema and '/' respectively.
// I.e., 'www.realizesec.com' becomes 'https:///www.realizesec.com/'
func normaliseURLScheme(u string) (string, error) {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(u, ".") {
		u, _ = strings.CutPrefix(u, ".")
	}

	if len(parsedUrl.Scheme) == 0 {
		u = "https://" + u
	}
	if !strings.HasSuffix(u, "/") {
		u = u + "/"
	}
	return u, nil
}

func extractHostname(urlStr string) (string, error) {
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsValidUrl tests a string to determine if it is a well-structured url or not.
func IsValidUrl(url string) bool {
	return validator.New().Var(url, "required,url") == nil
}
