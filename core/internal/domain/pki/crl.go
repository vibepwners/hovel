package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	MaximumCRLRevocations = 100_000
	MinimumCRLValidity    = 5 * time.Minute
	MaximumCRLValidity    = 7 * 24 * time.Hour
)

// CRLGeneration is one immutable, full certificate revocation list issued by
// a specific authority certificate generation.
type CRLGeneration struct {
	ID                           CRLGenerationID    `json:"id"`
	AuthorityID                  AuthorityID        `json:"authorityId"`
	IssuerGenerationID           GenerationID       `json:"issuerGenerationId"`
	Number                       uint64             `json:"number"`
	ThisUpdate                   time.Time          `json:"thisUpdate"`
	NextUpdate                   time.Time          `json:"nextUpdate"`
	RevocationIDs                []RevocationID     `json:"revocationIds"`
	SigningBackendID             BackendID          `json:"signingBackendId"`
	SigningBackendVersion        string             `json:"signingBackendVersion"`
	SigningBackendPackageDigest  string             `json:"signingBackendPackageDigest,omitempty"`
	SigningBackendCapabilityHash string             `json:"signingBackendCapabilityHash"`
	SignatureAlgorithm           SignatureAlgorithm `json:"signatureAlgorithm"`
	FingerprintSHA256            string             `json:"fingerprintSha256"`
	CRLDER                       []byte             `json:"crlDer"`
	CreatedAt                    time.Time          `json:"createdAt"`
}

type CRLGenerationArgs CRLGeneration

func NewCRLGeneration(args CRLGenerationArgs) (CRLGeneration, error) {
	if err := args.ID.Validate(); err != nil {
		return CRLGeneration{}, err
	}
	if err := args.AuthorityID.Validate(); err != nil {
		return CRLGeneration{}, err
	}
	if err := args.IssuerGenerationID.Validate(); err != nil {
		return CRLGeneration{}, err
	}
	if err := validateSequenceNumber(args.Number, "crl number"); err != nil {
		return CRLGeneration{}, err
	}
	thisUpdate := args.ThisUpdate.UTC().Truncate(time.Second)
	nextUpdate := args.NextUpdate.UTC().Truncate(time.Second)
	createdAt := args.CreatedAt.UTC().Truncate(time.Second)
	validity := nextUpdate.Sub(thisUpdate)
	if thisUpdate.IsZero() || nextUpdate.IsZero() || createdAt.IsZero() ||
		createdAt.Before(thisUpdate) || !createdAt.Before(nextUpdate) ||
		validity < MinimumCRLValidity || validity > MaximumCRLValidity {
		return CRLGeneration{}, errors.New("pki: crl update window is invalid")
	}
	if len(args.RevocationIDs) > MaximumCRLRevocations {
		return CRLGeneration{}, fmt.Errorf("pki: crl exceeds %d revocations", MaximumCRLRevocations)
	}
	revocationIDs := append([]RevocationID(nil), args.RevocationIDs...)
	for index, id := range revocationIDs {
		if err := id.Validate(); err != nil {
			return CRLGeneration{}, err
		}
		if index > 0 && revocationIDs[index-1] >= id {
			return CRLGeneration{}, errors.New("pki: crl revocation ids must be unique and sorted")
		}
	}
	if err := args.SigningBackendID.Validate(); err != nil {
		return CRLGeneration{}, err
	}
	if strings.TrimSpace(args.SigningBackendVersion) == "" || strings.TrimSpace(args.SigningBackendCapabilityHash) == "" {
		return CRLGeneration{}, errors.New("pki: crl signing backend commitment is required")
	}
	if err := args.SignatureAlgorithm.Validate(); err != nil {
		return CRLGeneration{}, err
	}
	fingerprint, err := normalizeSHA256Fingerprint(args.FingerprintSHA256, "crl fingerprint")
	if err != nil {
		return CRLGeneration{}, err
	}
	if len(args.CRLDER) == 0 || len(args.CRLDER) > MaximumCRLDERBytes {
		return CRLGeneration{}, errors.New("pki: crl der is empty or exceeds its size limit")
	}
	derDigest := sha256.Sum256(args.CRLDER)
	if fingerprint != hex.EncodeToString(derDigest[:]) {
		return CRLGeneration{}, errors.New("pki: crl fingerprint does not match its der")
	}
	return CRLGeneration{
		ID: args.ID, AuthorityID: args.AuthorityID, IssuerGenerationID: args.IssuerGenerationID,
		Number: args.Number, ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
		RevocationIDs:    append([]RevocationID(nil), revocationIDs...),
		SigningBackendID: args.SigningBackendID, SigningBackendVersion: strings.TrimSpace(args.SigningBackendVersion),
		SigningBackendPackageDigest:  strings.TrimSpace(args.SigningBackendPackageDigest),
		SigningBackendCapabilityHash: strings.TrimSpace(args.SigningBackendCapabilityHash),
		SignatureAlgorithm:           args.SignatureAlgorithm,
		FingerprintSHA256:            fingerprint, CRLDER: append([]byte(nil), args.CRLDER...), CreatedAt: createdAt,
	}, nil
}

func (g CRLGeneration) Clone() CRLGeneration {
	result := g
	result.RevocationIDs = append([]RevocationID(nil), g.RevocationIDs...)
	result.CRLDER = append([]byte(nil), g.CRLDER...)
	return result
}

func (g CRLGeneration) Validate() error {
	normalized, err := NewCRLGeneration(CRLGenerationArgs(g))
	if err != nil {
		return err
	}
	if normalized.ID != g.ID || normalized.AuthorityID != g.AuthorityID ||
		normalized.IssuerGenerationID != g.IssuerGenerationID || normalized.Number != g.Number ||
		!normalized.ThisUpdate.Equal(g.ThisUpdate) || !normalized.NextUpdate.Equal(g.NextUpdate) ||
		!slices.Equal(normalized.RevocationIDs, g.RevocationIDs) ||
		normalized.SigningBackendID != g.SigningBackendID || normalized.SigningBackendVersion != g.SigningBackendVersion ||
		normalized.SigningBackendPackageDigest != g.SigningBackendPackageDigest ||
		normalized.SigningBackendCapabilityHash != g.SigningBackendCapabilityHash ||
		normalized.SignatureAlgorithm != g.SignatureAlgorithm ||
		normalized.FingerprintSHA256 != g.FingerprintSHA256 || !slices.Equal(normalized.CRLDER, g.CRLDER) ||
		!normalized.CreatedAt.Equal(g.CreatedAt) {
		return errors.New("pki: crl generation is not canonical")
	}
	return nil
}

func (g CRLGeneration) FreshAt(currentTime time.Time) bool {
	currentTime = currentTime.UTC()
	return !currentTime.Before(g.ThisUpdate) && currentTime.Before(g.NextUpdate)
}
