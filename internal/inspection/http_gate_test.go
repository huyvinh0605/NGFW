package inspection

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestNormalizeGateHTTPRequestBounds(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "http://app.example/path", nil)
	limits := domain.DefaultRequestGateConfig()
	limits.MaxRawBodyBytes = 4
	if _, err := NormalizeGateHTTPRequest(base, []byte("12345"), limits); !errors.Is(err, ErrGateBodyTooLarge) {
		t.Fatalf("body limit not enforced: %v", err)
	}
	limits = domain.DefaultRequestGateConfig()
	limits.MaxHeaderCount = 1
	base.Header.Set("X-Test", "value")
	if _, err := NormalizeGateHTTPRequest(base, nil, limits); !errors.Is(err, ErrGateHeadersTooLarge) {
		t.Fatalf("header count limit not enforced: %v", err)
	}
	limits = domain.DefaultRequestGateConfig()
	limits.MaxHeaderBytes = 16
	if _, err := NormalizeGateHTTPRequest(base, nil, limits); !errors.Is(err, ErrGateHeadersTooLarge) {
		t.Fatalf("header byte limit not enforced: %v", err)
	}
	longURL := httptest.NewRequest(http.MethodGet, "http://app.example/"+strings.Repeat("a", 400), nil)
	limits = domain.DefaultRequestGateConfig()
	limits.MaxURLBytes = 256
	if _, err := NormalizeGateHTTPRequest(longURL, nil, limits); !errors.Is(err, ErrGateURLTooLong) {
		t.Fatalf("URL limit not enforced: %v", err)
	}
	if _, err := NormalizeGateHTTPRequest(nil, nil, domain.DefaultRequestGateConfig()); !errors.Is(err, ErrGateHTTPMalformed) {
		t.Fatalf("nil HTTP request was accepted: %v", err)
	}
}
