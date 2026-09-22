package domain

import "testing"

func TestParseServiceSelector(t *testing.T) {
	valid := []struct {
		input, canonical string
	}{
		{"tcp:80", "tcp:80"},
		{" tcp:80 ", "tcp:80"},
		{"TCP:443", "tcp:443"},
		{"udp:53", "udp:53"},
		{"tcp:80-90", "tcp:80-90"},
		{"icmp", "icmp"},
		{"icmpv6", "icmpv6"},
	}
	for _, tc := range valid {
		got, err := ParseServiceSelector(tc.input)
		if err != nil || got.Canonical() != tc.canonical {
			t.Errorf("ParseServiceSelector(%q) = %#v, %v; want %q", tc.input, got, err, tc.canonical)
		}
	}
	invalid := []string{"80", "443", "tcp", "tcp:", ":80", "tcp:http", "tcp:-1", "tcp:0", "tcp:65536", "udp:99999", "icmp:80", "tcp:80,", "tcp::80"}
	for _, input := range invalid {
		if _, err := ParseServiceSelector(input); err == nil {
			t.Errorf("ParseServiceSelector(%q) unexpectedly succeeded", input)
		}
	}
}

func TestCanonicalServiceListNormalizesAndDeduplicates(t *testing.T) {
	got, err := CanonicalServiceList([]string{"TCP:443", " tcp:80 ", "tcp:443", "udp:53"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcp:80", "tcp:443", "udp:53"}
	if len(got) != len(want) {
		t.Fatalf("canonical services=%#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("canonical services=%#v, want %#v", got, want)
		}
	}
}
