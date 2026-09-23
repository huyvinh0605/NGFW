package inspection

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func NormalizeApplication(raw string) domain.ApplicationIdentity {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" || value == "UNKNOWN" || value == "FAILED" || value == "UNDETECTED" {
		return domain.UnknownApplication()
	}
	identity := domain.ApplicationIdentity{Name: value, RawName: raw, Source: domain.ApplicationSourceSuricataAppProto, Confidence: domain.ApplicationConfidenceHigh}
	switch value {
	case "HTTP", "TLS", "DNS", "SSH":
	default:
		identity.Name = "OTHER"
		identity.Confidence = domain.ApplicationConfidenceMedium
	}
	return identity
}

func ApplicationFromObservation(obs Observation) domain.ApplicationIdentity {
	identity := obs.App.NormalizeZero()
	if identity.Name == "UNKNOWN" {
		if obs.Protocol != nil {
			switch {
			case obs.Protocol.HTTPHost != "" || obs.Protocol.HTTPMethod != "" || obs.Protocol.HTTPPath != "":
				identity = NormalizeApplication("HTTP")
			case obs.Protocol.TLSSNI != "" || obs.Protocol.TLSVersion != "":
				identity = NormalizeApplication("TLS")
			case obs.Protocol.DNSQuery != "" || obs.Protocol.DNSRecordType != "":
				identity = NormalizeApplication("DNS")
			case obs.Protocol.SSHBanner != "":
				identity = NormalizeApplication("SSH")
			}
		}
	}
	if obs.ObservedAt != nil {
		v := *obs.ObservedAt
		identity.FirstSeen, identity.LastSeen = &v, &v
	}
	return identity.NormalizeZero()
}

func MergeApplication(previous, next domain.ApplicationIdentity) domain.ApplicationIdentity {
	previous = previous.NormalizeZero()
	next = next.NormalizeZero()
	if previous.Name == "UNKNOWN" {
		next.Revision = previous.Revision + 1
		return next
	}
	if next.Name == "UNKNOWN" {
		return previous
	}
	rank := func(value domain.ApplicationConfidence) int {
		switch value {
		case domain.ApplicationConfidenceVerified:
			return 5
		case domain.ApplicationConfidenceHigh:
			return 4
		case domain.ApplicationConfidenceMedium:
			return 3
		case domain.ApplicationConfidenceLow:
			return 2
		default:
			return 1
		}
	}
	result := previous
	previousTime, previousHasTime := applicationObservedTime(previous)
	nextTime, nextHasTime := applicationObservedTime(next)
	timeOrder := 0
	if previousHasTime && nextHasTime {
		if nextTime.After(previousTime) {
			timeOrder = 1
		} else if nextTime.Before(previousTime) {
			timeOrder = -1
		}
	} else if nextHasTime {
		timeOrder = 1
	}
	if previous.Name == next.Name {
		if rank(next.Confidence) > rank(previous.Confidence) {
			result = next
		}
	} else {
		switch {
		case rank(next.Confidence) < rank(previous.Confidence):
			// Lower-authority evidence never downgrades an established identity.
		case timeOrder > 0:
			// A newer observation with equal or stronger authority can represent
			// a real protocol transition such as SMTP/HTTP upgrading to TLS.
			result = next
			result.Conflicted = false
		case timeOrder == 0 && rank(next.Confidence) == rank(previous.Confidence):
			// Deterministically retain the existing identity. Equal-authority
			// contradictory evidence at the same logical time is unsafe for an
			// automatic application guard.
			result.Conflicted = true
		case rank(next.Confidence) > rank(previous.Confidence):
			result = next
		}
	}
	if previous.FirstSeen != nil && (result.FirstSeen == nil || previous.FirstSeen.Before(*result.FirstSeen)) {
		v := *previous.FirstSeen
		result.FirstSeen = &v
	}
	if next.FirstSeen != nil && (result.FirstSeen == nil || next.FirstSeen.Before(*result.FirstSeen)) {
		v := *next.FirstSeen
		result.FirstSeen = &v
	}
	if previous.LastSeen != nil && (result.LastSeen == nil || previous.LastSeen.After(*result.LastSeen)) {
		v := *previous.LastSeen
		result.LastSeen = &v
	}
	if next.LastSeen != nil && (result.LastSeen == nil || next.LastSeen.After(*result.LastSeen)) {
		v := *next.LastSeen
		result.LastSeen = &v
	}
	result.Revision = previous.Revision + 1
	return result.NormalizeZero()
}

func applicationObservedTime(value domain.ApplicationIdentity) (time.Time, bool) {
	if value.LastSeen != nil {
		return value.LastSeen.UTC(), true
	}
	if value.FirstSeen != nil {
		return value.FirstSeen.UTC(), true
	}
	return time.Time{}, false
}

// InspectBoundedBytes is an explicit helper for tests/offline replay. It does
// not capture sockets and is never used as a fallback for a dead sensor.
func InspectBoundedBytes(protocolHint string, data []byte) (domain.ApplicationIdentity, error) {
	if len(data) == 0 {
		return domain.UnknownApplication(), errors.New("empty inspection input")
	}
	switch strings.ToLower(strings.TrimSpace(protocolHint)) {
	case "http":
		_, err := ParseHTTPRequest(data, DefaultHTTPLimits())
		if err != nil {
			return domain.UnknownApplication(), err
		}
		identity := NormalizeApplication("HTTP")
		identity.Confidence = domain.ApplicationConfidenceHigh
		return identity, nil
	case "tls", "ssl":
		if _, err := ParseTLSClientHello(data); err != nil {
			return domain.UnknownApplication(), err
		}
		return NormalizeApplication("TLS"), nil
	case "dns":
		if _, err := ParseDNSMessage(data, 32); err != nil {
			return domain.UnknownApplication(), err
		}
		return NormalizeApplication("DNS"), nil
	case "ssh":
		if !bytes.HasPrefix(data, []byte("SSH-")) {
			return domain.UnknownApplication(), errors.New("invalid SSH banner")
		}
		return NormalizeApplication("SSH"), nil
	default:
		return domain.UnknownApplication(), errors.New("unsupported protocol hint")
	}
}

func setObserved(identity domain.ApplicationIdentity, observed *time.Time) domain.ApplicationIdentity {
	if observed != nil {
		v := *observed
		identity.FirstSeen, identity.LastSeen = &v, &v
	}
	return identity
}
