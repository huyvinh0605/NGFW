package inspection

import "testing"

func TestParseDNSA(t *testing.T) {
	packet := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4}
	ctx, err := ParseDNSMessage(packet, 4)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Query != "www.example.com" || len(ctx.Answers) != 1 || ctx.Answers[0] != "1.2.3.4" {
		t.Fatalf("unexpected DNS context: %+v", ctx)
	}
}
