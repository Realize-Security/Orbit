package dns_analysers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestURLValidation(t *testing.T) {
	t.Run("URLs with FTP and HTTP/S schemas are expected to be valid.", func(t *testing.T) {
		assert.Equal(t, true, IsValidUrl("https://www.example.com"))
		assert.Equal(t, true, IsValidUrl("ftp://example.com"))
	})

	t.Run("URLs without schemas or subdomains are expected to be invalid.", func(t *testing.T) {
		assert.Equal(t, false, IsValidUrl("www.example.com"))
		assert.Equal(t, false, IsValidUrl("example.com"))
	})

	t.Run("Malformed are expected to be invalid.", func(t *testing.T) {
		assert.Equal(t, false, IsValidUrl("not-a-url"))
		assert.Equal(t, false, IsValidUrl(".example.com"))
		assert.Equal(t, false, IsValidUrl("example.com."))
	})

	t.Run("When invalid domains are normalised, they will become valid", func(t *testing.T) {
		noSchema, _ := normaliseURLScheme("www.example.com")
		assert.Equal(t, true, IsValidUrl(noSchema))
		noSubdomain, _ := normaliseURLScheme("example.com")
		assert.Equal(t, true, IsValidUrl(noSubdomain))
	})
}

func TestNormaliseAndExtractHostName(t *testing.T) {
	t.Run("Domains with schemas and paths are transformed to domain only.", func(t *testing.T) {
		mu, _ := normaliseAndExtractHostname("https://www.example.com/")
		assert.Equal(t, "www.example.com", mu)
	})
}

func TestNormaliseURLScheme(t *testing.T) {
	t.Run("Domains without a schema or path have 'https://' and '/' added where missing.", func(t *testing.T) {
		mu, _ := normaliseURLScheme("www.example.com")
		assert.Equal(t, "https://www.example.com/", mu)

		mu, _ = normaliseURLScheme("www.example.com/")
		assert.Equal(t, "https://www.example.com/", mu)

		mu, _ = normaliseURLScheme("https://www.example.com")
		assert.Equal(t, "https://www.example.com/", mu)

		mu, _ = normaliseURLScheme("example.com")
		assert.Equal(t, "https://example.com/", mu)

		mu, _ = normaliseURLScheme(".example.com")
		assert.Equal(t, "https://example.com/", mu)
	})
}
