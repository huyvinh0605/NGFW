//go:build !linux

package conntrack

import (
	"context"
)

type LinuxSource struct{}

func NewLinuxSource(_ string) (*LinuxSource, error)               { return nil, ErrUnsupportedPlatform }
func (s *LinuxSource) Subscribe(context.Context, EventSink) error { return ErrUnsupportedPlatform }
func (s *LinuxSource) Dump(context.Context, DumpLimits, func(Record) error) (DumpResult, error) {
	return DumpResult{}, ErrUnsupportedPlatform
}
func (s *LinuxSource) Get(context.Context, Identity) (Record, error) {
	return Record{}, ErrUnsupportedPlatform
}
func (s *LinuxSource) Close() error { return nil }
