package dataplane

import "fmt"

// M2 reserves only the upper 24 bits of ct mark. The lower byte belongs to
// existing integrations and is preserved on every cache mutation.
const (
	NGFWMarkMask       uint32 = 0xffffff00
	NGFWMarkEpochMask  uint32 = 0xfff00000
	NGFWMarkSourceMask uint32 = 0x000fc000
	NGFWMarkDestMask   uint32 = 0x00003f00
	MaxKernelEpoch            = 4095
	MaxZoneSlots              = 63
)

type CacheMark struct {
	Epoch                               uint16
	SourceZoneSlot, DestinationZoneSlot uint8
}

func PackCacheMark(mark CacheMark) (uint32, error) {
	if mark.Epoch == 0 || int(mark.Epoch) > MaxKernelEpoch {
		return 0, fmt.Errorf("epoch must be 1..%d", MaxKernelEpoch)
	}
	if mark.SourceZoneSlot == 0 || mark.SourceZoneSlot > MaxZoneSlots || mark.DestinationZoneSlot == 0 || mark.DestinationZoneSlot > MaxZoneSlots {
		return 0, fmt.Errorf("zone slots must be 1..%d", MaxZoneSlots)
	}
	return (uint32(mark.Epoch) << 20) | (uint32(mark.SourceZoneSlot) << 14) | (uint32(mark.DestinationZoneSlot) << 8), nil
}

func UnpackCacheMark(value uint32) (CacheMark, bool) {
	value &= NGFWMarkMask
	mark := CacheMark{Epoch: uint16((value & NGFWMarkEpochMask) >> 20), SourceZoneSlot: uint8((value & NGFWMarkSourceMask) >> 14), DestinationZoneSlot: uint8((value & NGFWMarkDestMask) >> 8)}
	return mark, mark.Epoch != 0 && mark.SourceZoneSlot != 0 && mark.DestinationZoneSlot != 0
}

func SetCacheMark(existing uint32, mark CacheMark) (uint32, error) {
	packed, err := PackCacheMark(mark)
	if err != nil {
		return existing, err
	}
	return (existing &^ NGFWMarkMask) | packed, nil
}
func ClearCacheMark(existing uint32, ownsMark bool) uint32 {
	if !ownsMark {
		return existing
	}
	return existing &^ NGFWMarkMask
}
func CacheHit(existing uint32, expected CacheMark, ownsMark bool) bool {
	if !ownsMark {
		return false
	}
	packed, err := PackCacheMark(expected)
	return err == nil && existing&NGFWMarkMask == packed
}

func CacheModeAllowed(zoneCount int, foreignUpperBits bool) bool {
	return zoneCount > 0 && zoneCount <= MaxZoneSlots && !foreignUpperBits
}
