package pki

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func VerifyBundle(bundle domainpki.Bundle) error {
	return VerifyBundleAt(bundle, time.Now().UTC())
}

func VerifyBundleAt(bundle domainpki.Bundle, currentTime time.Time) error {
	if err := bundle.Validate(); err != nil {
		return fmt.Errorf("pki: validate credential bundle: %w", err)
	}
	certificate, err := parseBundleCertificate(bundle.Certificate.Data, "leaf")
	if err != nil {
		return err
	}
	if !bytes.Equal(certificate.RawSubjectPublicKeyInfo, bundle.PublicKey.Data) {
		return errors.New("pki: bundle public key does not match the leaf certificate")
	}
	certificateDigest := sha256.Sum256(bundle.Certificate.Data)
	publicKeyDigest := sha256.Sum256(bundle.PublicKey.Data)
	if bundle.Fingerprints.CertificateSHA256 != hex.EncodeToString(certificateDigest[:]) ||
		bundle.Fingerprints.PublicKeySHA256 != hex.EncodeToString(publicKeyDigest[:]) {
		return errors.New("pki: bundle fingerprints do not match encoded material")
	}
	if !certificate.NotBefore.Equal(bundle.NotBefore) || !certificate.NotAfter.Equal(bundle.NotAfter) {
		return errors.New("pki: bundle validity does not match the leaf certificate")
	}
	if err := verifyBundlePurpose(certificate, bundle.Purpose); err != nil {
		return err
	}
	if bundle.PrivateKey != nil {
		if err := verifyBundlePrivateKey(bundle.PrivateKey.Data, bundle.PublicKey.Data); err != nil {
			return err
		}
	}
	chain, err := parseCertificateMembers(bundle.Chain, "chain")
	if err != nil {
		return err
	}
	trust, err := parseCertificateMembers(bundle.TrustAnchors, "trust anchor")
	if err != nil {
		return err
	}
	if err := verifyBundleChain(certificate, chain, trust, currentTime, bundle.Purpose); err != nil {
		return err
	}
	certificatesByGeneration := make(map[domainpki.GenerationID]*x509.Certificate, 1+len(chain)+len(trust))
	certificatesByGeneration[bundle.CertificateGenerationID] = certificate
	for index, member := range bundle.Chain {
		certificatesByGeneration[member.GenerationID] = chain[index]
	}
	for index, member := range bundle.TrustAnchors {
		certificatesByGeneration[member.GenerationID] = trust[index]
	}
	for _, member := range bundle.CertificateRevocationLists {
		crl, err := x509.ParseRevocationList(member.Data)
		if err != nil {
			return fmt.Errorf("pki: parse bundle crl %q: %w", member.GenerationID, err)
		}
		if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || !crl.NextUpdate.After(crl.ThisUpdate) ||
			currentTime.Before(crl.ThisUpdate) || !currentTime.Before(crl.NextUpdate) {
			return fmt.Errorf("pki: bundle crl %q has invalid update bounds", member.GenerationID)
		}
		issuer, ok := certificatesByGeneration[member.IssuerGenerationID]
		if !ok {
			return fmt.Errorf("pki: bundle crl %q references unavailable issuer generation %q", member.GenerationID, member.IssuerGenerationID)
		}
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || crl.CheckSignatureFrom(issuer) != nil {
			return fmt.Errorf("pki: bundle crl %q does not validate to a supplied issuer", member.GenerationID)
		}
		for generationID, supplied := range certificatesByGeneration {
			if generationID == member.IssuerGenerationID || !bytes.Equal(supplied.RawIssuer, issuer.RawSubject) {
				continue
			}
			for _, revoked := range crl.RevokedCertificateEntries {
				if revoked.SerialNumber.Cmp(supplied.SerialNumber) == 0 && !revoked.RevocationTime.After(currentTime) {
					return fmt.Errorf("pki: bundle crl %q revokes supplied certificate generation %q", member.GenerationID, generationID)
				}
			}
		}
	}
	return nil
}

func DecodeAndVerifyBundleJSON(encoded []byte, currentTime time.Time) (domainpki.Bundle, error) {
	bundle, err := domainpki.DecodeBundleJSON(encoded)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	if err := VerifyBundleAt(bundle, currentTime); err != nil {
		return domainpki.Bundle{}, err
	}
	return bundle.Clone(), nil
}

func parseBundleCertificate(der []byte, field string) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse bundle %s certificate: %w", field, err)
	}
	if !bytes.Equal(certificate.Raw, der) {
		return nil, fmt.Errorf("pki: bundle %s certificate contains trailing data", field)
	}
	return certificate, nil
}

func parseCertificateMembers(members []domainpki.CertificateMember, field string) ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0, len(members))
	for _, member := range members {
		certificate, err := parseBundleCertificate(member.Data, field)
		if err != nil {
			return nil, err
		}
		result = append(result, certificate)
	}
	return result, nil
}

func verifyBundlePrivateKey(privateDER, expectedSPKI []byte) error {
	privateKey, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return fmt.Errorf("pki: parse bundle private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("pki: bundle private key type %T cannot sign", privateKey)
	}
	actualSPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("pki: marshal bundle private-key public key: %w", err)
	}
	if !bytes.Equal(actualSPKI, expectedSPKI) {
		return errors.New("pki: bundle private key does not match the public key")
	}
	return nil
}

func verifyBundleChain(leaf *x509.Certificate, chain, trust []*x509.Certificate, currentTime time.Time, purpose domainpki.Purpose) error {
	if currentTime.IsZero() {
		return errors.New("pki: bundle verification time is required")
	}
	current := leaf
	for _, parent := range chain {
		if !bytes.Equal(current.RawIssuer, parent.RawSubject) {
			return errors.New("pki: bundle chain issuer and subject names do not match")
		}
		if err := current.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("pki: verify bundle chain signature: %w", err)
		}
		current = parent
	}
	if len(trust) == 0 {
		if len(chain) != 0 || !bytes.Equal(current.RawIssuer, current.RawSubject) {
			return errors.New("pki: bundle chain does not terminate in a trust anchor")
		}
		if err := current.CheckSignatureFrom(current); err != nil {
			return fmt.Errorf("pki: verify bundle self-signed certificate: %w", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(current)
		return verifyPKIXBundleChain(leaf, chain, roots, currentTime, purpose)
	}
	roots := x509.NewCertPool()
	terminatesAtTrust := false
	for _, anchor := range trust {
		if err := anchor.CheckSignatureFrom(anchor); err != nil {
			return fmt.Errorf("pki: verify bundle trust anchor: %w", err)
		}
		roots.AddCert(anchor)
		if bytes.Equal(current.Raw, anchor.Raw) || bytes.Equal(current.RawIssuer, anchor.RawSubject) && current.CheckSignatureFrom(anchor) == nil {
			terminatesAtTrust = true
		}
	}
	if !terminatesAtTrust {
		return errors.New("pki: bundle chain does not validate to a supplied trust anchor")
	}
	return verifyPKIXBundleChain(leaf, chain, roots, currentTime, purpose)
}

func verifyPKIXBundleChain(leaf *x509.Certificate, chain []*x509.Certificate, roots *x509.CertPool, currentTime time.Time, purpose domainpki.Purpose) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range chain {
		intermediates.AddCert(certificate)
	}
	for _, usage := range pkixKeyUsages(purpose) {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   currentTime,
			KeyUsages:     []x509.ExtKeyUsage{usage},
		}); err != nil {
			return fmt.Errorf("pki: verify bundle pkix path for %s: %w", purpose, err)
		}
	}
	return nil
}

func pkixKeyUsages(purpose domainpki.Purpose) []x509.ExtKeyUsage {
	switch purpose {
	case domainpki.PurposeTLSServer, domainpki.PurposeMTLSServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case domainpki.PurposeTLSClient, domainpki.PurposeMTLSClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case domainpki.PurposeDualRoleMTLS:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case domainpki.PurposeCodeSigning:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
}

func verifyBundlePurpose(certificate *x509.Certificate, purpose domainpki.Purpose) error {
	requireServer := purpose == domainpki.PurposeTLSServer || purpose == domainpki.PurposeMTLSServer || purpose == domainpki.PurposeDualRoleMTLS
	requireClient := purpose == domainpki.PurposeTLSClient || purpose == domainpki.PurposeMTLSClient || purpose == domainpki.PurposeDualRoleMTLS
	requireCodeSigning := purpose == domainpki.PurposeCodeSigning
	server, client, codeSigning := false, false, false
	for _, usage := range certificate.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth
		client = client || usage == x509.ExtKeyUsageClientAuth
		codeSigning = codeSigning || usage == x509.ExtKeyUsageCodeSigning
	}
	if requireServer && !server || requireClient && !client || requireCodeSigning && !codeSigning {
		return fmt.Errorf("pki: leaf certificate usages do not satisfy bundle purpose %q", purpose)
	}
	return nil
}
