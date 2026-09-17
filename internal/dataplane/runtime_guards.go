package dataplane

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// RuntimeGuardManager mutates only the engine-owned ngfw_runtime table. It
// never flushes the policy table or conntrack, so a failed management request
// cannot remove an unrelated M1 rule.
type RuntimeGuardManager struct{ Nft *NftRunner }

func NewRuntimeGuardManager(nft *NftRunner) *RuntimeGuardManager {
	return &RuntimeGuardManager{Nft: nft}
}

func (g *RuntimeGuardManager) AddSourceBlock(ctx context.Context, indicator string, expires time.Time) error {
	address, err := netip.ParseAddr(strings.TrimSpace(indicator))
	if err != nil || !address.Is4() {
		return fmt.Errorf("temporary block requires IPv4 address")
	}
	ttl := time.Until(expires)
	if ttl <= 0 {
		return fmt.Errorf("temporary block is already expired")
	}
	return g.apply(ctx, fmt.Sprintf("add element inet ngfw_runtime source_blocks { %s timeout %s }\n", address, nftDuration(ttl)))
}
func (g *RuntimeGuardManager) RemoveSourceBlock(ctx context.Context, indicator string) error {
	address, err := netip.ParseAddr(strings.TrimSpace(indicator))
	if err != nil || !address.Is4() {
		return fmt.Errorf("temporary block requires IPv4 address")
	}
	return g.apply(ctx, fmt.Sprintf("delete element inet ngfw_runtime source_blocks { %s }\n", address))
}
func (g *RuntimeGuardManager) RevokeSession(ctx context.Context, session domain.RuntimeSession) error {
	if session.Identity.ID == 0 {
		return fmt.Errorf("cannot revoke session without conntrack ID")
	}
	return g.apply(ctx, fmt.Sprintf("add element inet ngfw_runtime revoked_ctids { %d }\n", session.Identity.ID))
}
func (g *RuntimeGuardManager) ReleaseSession(ctx context.Context, session domain.RuntimeSession) error {
	if session.Identity.ID == 0 {
		return nil
	}
	return g.apply(ctx, fmt.Sprintf("delete element inet ngfw_runtime revoked_ctids { %d }\n", session.Identity.ID))
}
func (g *RuntimeGuardManager) apply(ctx context.Context, script string) error {
	if g == nil || g.Nft == nil {
		return fmt.Errorf("runtime guard manager is unavailable")
	}
	return g.Nft.ApplyRuntimeMutation(ctx, script)
}
func nftDuration(value time.Duration) string {
	seconds := int64(value / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10) + "s"
}
