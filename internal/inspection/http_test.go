package inspection

import "testing"

func TestParseHTTPRequestBounded(t *testing.T) {
	raw := []byte("GET /a?x=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n\r\nhello")
	r, err := ParseHTTPRequest(raw, DefaultHTTPLimits())
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "GET" || r.Host != "example.test" || r.Query != "x=1" || string(r.Body) != "hello" {
		t.Fatalf("unexpected request: %+v", r)
	}
}
func TestParseHTTPRequestLimit(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n123456")
	l := DefaultHTTPLimits()
	l.MaxBodySize = 2
	r, err := ParseHTTPRequest(raw, l)
	if err != nil {
		t.Fatal(err)
	}
	if !r.BodyTruncated || string(r.Body) != "12" {
		t.Fatalf("body limit not enforced: %+v", r)
	}
}
