package pki

import "fmt"

// MaximumSequenceNumber is the largest generation or revision that Hovel can
// persist through every supported storage adapter. Keeping the bound in the
// domain contract prevents an API-valid value from failing only at SQLite.
const MaximumSequenceNumber uint64 = 1<<63 - 1

func validateSequenceNumber(value uint64, field string) error {
	if value == 0 {
		return fmt.Errorf("pki: %s must be positive", field)
	}
	if value > MaximumSequenceNumber {
		return fmt.Errorf("pki: %s exceeds the supported range", field)
	}
	return nil
}
