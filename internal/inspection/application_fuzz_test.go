package inspection

import "testing"

func FuzzApplicationBytes(f *testing.F) {
	f.Add("http", []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	f.Add("ssh", []byte("SSH-2.0-fixture\r\n"))
	f.Add("tls", []byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add("dns", []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, hint string, data []byte) {
		if len(hint) > 32 || len(data) > 1<<20 {
			return
		}
		identity, err := InspectBoundedBytes(hint, data)
		if err == nil && (identity.Name == "" || !identity.Source.Valid() || !identity.Confidence.Valid()) {
			t.Fatalf("successful parse returned invalid identity: %#v", identity)
		}
	})
}
