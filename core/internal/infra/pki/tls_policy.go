package pki

import (
	"crypto/tls"
	"fmt"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

// TLSCurvePreferences maps an already-resolved compatibility snapshot to Go
// TLS groups. It never adds a fallback that is absent from the persisted
// contract.
func TLSCurvePreferences(policy domainpki.KeyEstablishmentPolicy, groups []domainpki.TLSNamedGroup) ([]tls.CurveID, error) {
	if err := domainpki.ValidateKeyEstablishment(policy, groups); err != nil {
		return nil, err
	}
	result := make([]tls.CurveID, 0, len(groups))
	for _, group := range groups {
		curve, err := tlsCurve(group)
		if err != nil {
			return nil, err
		}
		result = append(result, curve)
	}
	return result, nil
}

func TLSCurvePreferencesForBundle(bundle domainpki.Bundle) ([]tls.CurveID, error) {
	return TLSCurvePreferencesForBundleAt(bundle, time.Now().UTC())
}

func TLSCurvePreferencesForBundleAt(
	bundle domainpki.Bundle,
	currentTime time.Time,
) ([]tls.CurveID, error) {
	if err := VerifyBundleAt(bundle, currentTime); err != nil {
		return nil, fmt.Errorf("pki: validate tls credential bundle: %w", err)
	}
	return TLSCurvePreferences(bundle.KeyEstablishmentPolicy, bundle.TLSNamedGroups)
}

func tlsCurve(group domainpki.TLSNamedGroup) (tls.CurveID, error) {
	switch group {
	case domainpki.TLSNamedGroupX25519MLKEM768:
		return tls.X25519MLKEM768, nil
	case domainpki.TLSNamedGroupP256MLKEM768:
		return tls.SecP256r1MLKEM768, nil
	case domainpki.TLSNamedGroupP384MLKEM1024:
		return tls.SecP384r1MLKEM1024, nil
	case domainpki.TLSNamedGroupX25519:
		return tls.X25519, nil
	case domainpki.TLSNamedGroupP256:
		return tls.CurveP256, nil
	case domainpki.TLSNamedGroupP384:
		return tls.CurveP384, nil
	case domainpki.TLSNamedGroupP521:
		return tls.CurveP521, nil
	default:
		return 0, fmt.Errorf("pki: unsupported tls named group %q", group)
	}
}

func IsHybridPostQuantumTLSCurve(curve tls.CurveID) bool {
	switch curve {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}
