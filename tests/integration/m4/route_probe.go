//go:build linux

// This helper is run only inside a disposable Linux network namespace.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kltngfw/ngfw/internal/dataplane"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	routing := dataplane.TPROXYRouting{IP: dataplane.NewExecIPCommandRunner("ip")}
	if err := routing.Ensure(ctx); err != nil {
		fail("ensure", err)
	}
	if err := routing.Verify(ctx); err != nil {
		fail("verify", err)
	}
	if err := routing.Ensure(ctx); err != nil {
		fail("idempotent ensure", err)
	}
	if err := routing.Remove(ctx); err != nil {
		fail("remove", err)
	}
	if err := routing.Verify(ctx); err == nil {
		fail("removal verification", fmt.Errorf("TPROXY route remained after removal"))
	}
	fmt.Println("PASS: TPROXY policy route ensure/verify/idempotence/remove")
}

func fail(stage string, err error) {
	fmt.Fprintln(os.Stderr, stage+":", err)
	os.Exit(1)
}
