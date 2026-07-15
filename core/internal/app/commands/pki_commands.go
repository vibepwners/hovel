package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	defaultPKIActorID           = "hovel-cli"
	defaultPKIOperationID       = "pki"
	pkiCorrelationBytes         = 16
	pkiIdempotencyKeyOptionName = "idempotency-key"
)

type PKIRequestScope struct {
	ActorID                 string
	OperationID             string
	CorrelationID           string
	ApproveSigningLease     bool
	ApprovePrivateKeyExport bool
}

// PKIControlClient is an optional capability of the daemon client used by
// command handlers. Keeping it separate lets non-PKI test clients and small
// front ends implement only the daemon features they consume.
type PKIControlClient interface {
	PKIStatus(context.Context) (apppki.WorkspaceStatus, error)
	InitializePKI(context.Context, PKIRequestScope, bool) (apppki.WorkspaceStatus, error)
	ListPKIBackends(context.Context) ([]domainpki.BackendDescriptor, error)
	ListPKIProfiles(context.Context) ([]domainpki.Profile, error)
	ListPKIAuthorities(context.Context) ([]domainpki.Authority, error)
	InspectPKIAuthority(context.Context, domainpki.AuthorityID) (apppki.AuthorityInspection, error)
	CreatePKIAuthority(context.Context, PKIRequestScope, apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error)
	UnlockPKIAuthority(context.Context, PKIRequestScope, domainpki.AuthorityID, time.Duration) (apppki.SigningLease, error)
	LockPKIAuthority(context.Context, PKIRequestScope, domainpki.AuthorityID) error
	ListPKICertificates(context.Context) ([]domainpki.CertificateGeneration, error)
	InspectPKICertificate(context.Context, domainpki.GenerationID) (domainpki.CertificateGeneration, error)
	IssuePKICertificate(context.Context, PKIRequestScope, apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error)
	RenewPKICertificate(context.Context, PKIRequestScope, apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error)
	RotatePKICertificate(context.Context, PKIRequestScope, apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error)
	RevokePKICertificate(context.Context, PKIRequestScope, apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error)
	InspectPKIRevocation(context.Context, domainpki.RevocationID) (domainpki.Revocation, error)
	InspectPKIGenerationRevocation(context.Context, domainpki.GenerationID) (domainpki.Revocation, error)
	ListPKIRevocations(context.Context, domainpki.AuthorityID) ([]domainpki.Revocation, error)
	PublishPKICRL(context.Context, PKIRequestScope, apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error)
	InspectPKICRL(context.Context, domainpki.CRLGenerationID) (domainpki.CRLGeneration, error)
	ListPKICRLs(context.Context, domainpki.AuthorityID) ([]domainpki.CRLGeneration, error)
	ListPKIAssignments(context.Context) ([]domainpki.Assignment, error)
	InspectPKIAssignment(context.Context, domainpki.AssignmentID) (apppki.AssignmentInspection, error)
	BindPKIAssignment(context.Context, PKIRequestScope, apppki.BindAssignmentRequest) (domainpki.Assignment, error)
	StagePKIAssignment(context.Context, PKIRequestScope, apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error)
	ActivatePKIAssignment(context.Context, PKIRequestScope, apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error)
	UnbindPKIAssignment(context.Context, PKIRequestScope, apppki.UnbindAssignmentRequest) (domainpki.Assignment, error)
	ListPKITrustSets(context.Context) ([]domainpki.TrustSet, error)
	InspectPKITrustSet(context.Context, domainpki.TrustSetID) (apppki.TrustSetInspection, error)
	CreatePKITrustSet(context.Context, PKIRequestScope, apppki.CreateTrustSetRequest) (domainpki.TrustSet, error)
	StagePKITrustSet(context.Context, PKIRequestScope, apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error)
	ActivatePKITrustSet(context.Context, PKIRequestScope, apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error)
}

func pkiDefinitions(runtime Runtime) []Definition {
	workspaceJSON := []Option{stringOption("workspace", "w", "Workspace path"), boolOption("json", "j", "Emit JSON output")}
	return []Definition{
		{Path: []string{"pki", "status"}, Summary: "Inspect workspace PKI custody status.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiStatusHandler(runtime)},
		{Path: []string{"pki", "init"}, Summary: "Initialize workspace PKI custody.", RequiresDaemon: true, Options: appendOptions(workspaceJSON, boolOption("yes", "y", "Confirm PKI initialization")), Handler: pkiInitHandler(runtime)},
		{Path: []string{"pki", "backend", "list"}, Summary: "List available PKI crypto backends.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiBackendsHandler(runtime)},
		{Path: []string{"pki", "profile", "list"}, Summary: "List built-in PKI profiles.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiProfilesHandler(runtime)},
		{Path: []string{"pki", "authority", "list"}, Summary: "List certificate authorities.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiAuthoritiesHandler(runtime)},
		{Path: []string{"pki", "authority", "inspect"}, Summary: "Inspect a certificate authority.", RequiresDaemon: true, Positionals: []Positional{{Name: "authority", Help: "Authority ID", Required: true}}, Options: workspaceJSON, Handler: pkiAuthorityInspectHandler(runtime)},
		{
			Path: []string{"pki", "authority", "create"}, Summary: "Create a root or subordinate certificate authority.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "name", Help: "Authority display name", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("role", "r", "Authority role: root or subordinate"), stringOption("parent", "", "Parent authority ID for a subordinate"),
				stringOption("profile", "", "Authority profile ID"), stringOption("backend", "", "Crypto backend ID"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm authority creation")),
			Handler: pkiAuthorityCreateHandler(runtime),
		},
		{
			Path: []string{"pki", "authority", "unlock"}, Summary: "Grant a scoped authority signing lease.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "authority", Help: "Authority ID", Required: true}},
			Options:     appendOptions(workspaceJSON, stringOption("duration", "d", "Lease duration, default 5m and maximum 15m"), boolOption("approve", "", "Explicitly approve signing-key use")),
			Handler:     pkiAuthorityUnlockHandler(runtime),
		},
		{Path: []string{"pki", "authority", "lock"}, Summary: "Revoke the caller's authority signing lease.", RequiresDaemon: true, Positionals: []Positional{{Name: "authority", Help: "Authority ID", Required: true}}, Options: workspaceJSON, Handler: pkiAuthorityLockHandler(runtime)},
		{Path: []string{"pki", "certificate", "list"}, Summary: "List immutable certificate generations.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiCertificatesHandler(runtime)},
		{Path: []string{"pki", "certificate", "inspect"}, Summary: "Inspect a certificate generation.", RequiresDaemon: true, Positionals: []Positional{{Name: "generation", Help: "Certificate generation ID", Required: true}}, Options: workspaceJSON, Handler: pkiCertificateInspectHandler(runtime)},
		{
			Path: []string{"pki", "certificate", "issue"}, Summary: "Issue a leaf certificate through an unlocked authority.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "name", Help: "Certificate subject name", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("issuer", "i", "Issuing authority ID"), stringOption("profile", "", "Leaf profile ID"), stringOption("backend", "", "Subject-key crypto backend ID"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm certificate issuance")),
			Handler: pkiCertificateIssueHandler(runtime),
		},
		{
			Path: []string{"pki", "certificate", "renew"}, Summary: "Renew a leaf certificate while reusing its key.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "generation", Help: "Active source certificate generation ID", Required: true}},
			Options: appendOptions(workspaceJSON, stringOption("generation-id", "", "Stable new generation ID"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm certificate renewal")),
			Handler: pkiCertificateRenewHandler(runtime),
		},
		{
			Path: []string{"pki", "certificate", "rotate"}, Summary: "Rotate a leaf certificate onto a new key.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "generation", Help: "Active source certificate generation ID", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("generation-id", "", "Stable new generation ID"), stringOption("key-id", "", "Stable new key ID"),
				stringOption("backend", "", "Subject-key crypto backend ID"), pkiIdempotencyOption(),
				boolOption("yes", "y", "Confirm certificate rotation")),
			Handler: pkiCertificateRotateHandler(runtime),
		},
		{
			Path: []string{"pki", "certificate", "revoke"}, Summary: "Revoke a certificate generation and degrade affected assignments.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "generation", Help: "Certificate generation ID", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("reason", "r", "RFC 5280 revocation reason"),
				stringOption("effective-at", "", "Effective time in RFC3339; defaults to now"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm certificate revocation")),
			Handler: pkiCertificateRevokeHandler(runtime),
		},
		{Path: []string{"pki", "revocation", "list"}, Summary: "List revocations issued by an authority.", RequiresDaemon: true, Positionals: []Positional{{Name: "authority", Help: "Issuing authority ID", Required: true}}, Options: workspaceJSON, Handler: pkiRevocationsHandler(runtime)},
		{Path: []string{"pki", "revocation", "inspect"}, Summary: "Inspect a revocation record.", RequiresDaemon: true, Positionals: []Positional{{Name: "revocation", Help: "Revocation ID", Required: true}}, Options: workspaceJSON, Handler: pkiRevocationInspectHandler(runtime)},
		{Path: []string{"pki", "revocation", "generation"}, Summary: "Inspect the revocation for a certificate generation.", RequiresDaemon: true, Positionals: []Positional{{Name: "generation", Help: "Certificate generation ID", Required: true}}, Options: workspaceJSON, Handler: pkiGenerationRevocationInspectHandler(runtime)},
		{
			Path: []string{"pki", "crl", "publish"}, Summary: "Publish a signed full CRL for an authority.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "authority", Help: "Issuing authority ID", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("issuer-generation", "", "Active authority generation ID; defaults to the current generation"),
				stringOption("valid-for", "", "CRL validity duration; defaults to 24h"),
				stringOption("signature-algorithm", "", "Concrete signature algorithm; defaults from the issuer key"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm CRL publication")),
			Handler: pkiCRLPublishHandler(runtime),
		},
		{Path: []string{"pki", "crl", "list"}, Summary: "List CRL generations published by an authority.", RequiresDaemon: true, Positionals: []Positional{{Name: "authority", Help: "Issuing authority ID", Required: true}}, Options: workspaceJSON, Handler: pkiCRLsHandler(runtime)},
		{Path: []string{"pki", "crl", "inspect"}, Summary: "Inspect an immutable CRL generation.", RequiresDaemon: true, Positionals: []Positional{{Name: "crl", Help: "CRL generation ID", Required: true}}, Options: workspaceJSON, Handler: pkiCRLInspectHandler(runtime)},
		{Path: []string{"pki", "assignment", "list"}, Summary: "List PKI consumer assignments.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiAssignmentsHandler(runtime)},
		{Path: []string{"pki", "assignment", "inspect"}, Summary: "Inspect a resolved PKI assignment.", RequiresDaemon: true, Positionals: []Positional{{Name: "assignment", Help: "Assignment ID", Required: true}}, Options: workspaceJSON, Handler: pkiAssignmentInspectHandler(runtime)},
		{
			Path: []string{"pki", "assignment", "bind"}, Summary: "Bind a consumer to a PKI profile and trust set.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "consumer", Help: "Canonical consumer ID", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("id", "", "Stable assignment ID"), stringOption("consumer-type", "", "Consumer type"),
				stringOption("purpose", "", "Certificate purpose"), stringOption("profile", "", "Certificate profile ID"),
				stringOption("trust-set", "", "Peer trust-set ID"), stringOption("rotation-policy", "", "Optional rotation policy ID"),
				pkiIdempotencyOption(), boolOption("yes", "y", "Confirm assignment binding")),
			Handler: pkiAssignmentBindHandler(runtime),
		},
		{
			Path: []string{"pki", "assignment", "stage"}, Summary: "Stage a certificate generation on an assignment.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "assignment", Help: "Assignment ID", Required: true}, {Name: "generation", Help: "Certificate generation ID", Required: true}},
			Options:     appendOptions(workspaceJSON, stringOption("revision", "", "Expected assignment revision"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm assignment staging")),
			Handler:     pkiAssignmentStageHandler(runtime),
		},
		{Path: []string{"pki", "assignment", "activate"}, Summary: "Activate an assignment's staged generation.", RequiresDaemon: true, Positionals: []Positional{{Name: "assignment", Help: "Assignment ID", Required: true}}, Options: appendOptions(workspaceJSON, stringOption("revision", "", "Expected assignment revision"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm assignment activation")), Handler: pkiAssignmentActivateHandler(runtime)},
		{Path: []string{"pki", "assignment", "unbind"}, Summary: "Retire an assignment and preserve its history.", RequiresDaemon: true, Positionals: []Positional{{Name: "assignment", Help: "Assignment ID", Required: true}}, Options: appendOptions(workspaceJSON, stringOption("revision", "", "Expected assignment revision"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm assignment retirement")), Handler: pkiAssignmentUnbindHandler(runtime)},
		{Path: []string{"pki", "trust", "list"}, Summary: "List PKI trust sets.", RequiresDaemon: true, Options: workspaceJSON, Handler: pkiTrustSetsHandler(runtime)},
		{Path: []string{"pki", "trust", "inspect"}, Summary: "Inspect a resolved PKI trust set.", RequiresDaemon: true, Positionals: []Positional{{Name: "trust-set", Help: "Trust-set ID", Required: true}}, Options: workspaceJSON, Handler: pkiTrustSetInspectHandler(runtime)},
		{
			Path: []string{"pki", "trust", "create"}, Summary: "Create a pending PKI trust set.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "name", Help: "Trust-set display name", Required: true}},
			Options:     appendOptions(workspaceJSON, stringOption("id", "", "Stable trust-set ID"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm trust-set creation")),
			Handler:     pkiTrustSetCreateHandler(runtime),
		},
		{
			Path: []string{"pki", "trust", "stage"}, Summary: "Stage an immutable PKI trust generation.", RequiresDaemon: true,
			Positionals: []Positional{{Name: "trust-set", Help: "Trust-set ID", Required: true}},
			Options: appendOptions(workspaceJSON,
				stringOption("revision", "", "Expected trust-set revision"), stringOption("generation-id", "", "Stable trust generation ID"),
				stringOption("anchors", "", "Comma-separated anchor certificate generation IDs"),
				stringOption("intermediates", "", "Comma-separated intermediate certificate generation IDs"),
				stringOption("crls", "", "Comma-separated CRL generation IDs"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm trust generation staging")),
			Handler: pkiTrustSetStageHandler(runtime),
		},
		{Path: []string{"pki", "trust", "activate"}, Summary: "Activate a staged PKI trust generation.", RequiresDaemon: true, Positionals: []Positional{{Name: "trust-set", Help: "Trust-set ID", Required: true}}, Options: appendOptions(workspaceJSON, stringOption("revision", "", "Expected trust-set revision"), pkiIdempotencyOption(), boolOption("yes", "y", "Confirm trust-set activation")), Handler: pkiTrustSetActivateHandler(runtime)},
	}
}

func pkiIdempotencyOption() Option {
	return stringOption(pkiIdempotencyKeyOptionName, "", "Stable retry key")
}

func appendOptions(base []Option, extra ...Option) []Option {
	result := append([]Option(nil), base...)
	return append(result, extra...)
}

func dialPKIClient(ctx context.Context, runtime Runtime, workspacePath string) (PKIControlClient, func(), error) {
	client, closeClient, err := dialDaemonRunClient(ctx, runtime, workspacePath)
	if err != nil {
		return nil, nil, err
	}
	pkiClient, ok := client.(PKIControlClient)
	if !ok {
		closeClient()
		return nil, nil, errors.New("daemon client does not support PKI control")
	}
	return pkiClient, closeClient, nil
}

func pkiScope(invocation Invocation, approveSigning bool) (PKIRequestScope, error) {
	random := make([]byte, pkiCorrelationBytes)
	if _, err := rand.Read(random); err != nil {
		return PKIRequestScope{}, fmt.Errorf("generate PKI correlation ID: %w", err)
	}
	return PKIRequestScope{
		ActorID: defaultPKIActorID, OperationID: defaultPKIOperationID,
		CorrelationID: "pki-" + hex.EncodeToString(random), ApproveSigningLease: approveSigning,
	}, nil
}

func confirmPKIMutation(ctx context.Context, invocation Invocation, action string) error {
	if invocation.Flag("yes") {
		return nil
	}
	if invocation.NonInteractive || invocation.Input == nil {
		return fmt.Errorf("%s requires confirmation; pass --yes in non-interactive mode", action)
	}
	prompt := ConfirmationPrompt{Title: "CONFIRM PKI CHANGE", Action: action, RequiredLiteral: "yes", Fields: []ConfirmationField{{Label: "Action", Value: action}}}
	answer, err := invocation.Input.Confirm(ctx, prompt)
	if err != nil {
		return err
	}
	if !answer.Confirmed(prompt) {
		return fmt.Errorf("%s was not confirmed", action)
	}
	return nil
}

func withPKIClient(runtime Runtime, fn func(context.Context, Invocation, PKIControlClient) (Result, error)) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialPKIClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		return fn(ctx, invocation, client)
	}
}

func pkiStatusHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		status, err := client.PKIStatus(ctx)
		if err != nil {
			return Result{}, err
		}
		human := "Workspace PKI is not initialized"
		if status.Initialized {
			human = fmt.Sprintf("Workspace PKI initialized with master key %s", status.ActiveKeyVersion)
		}
		if status.Error != "" {
			human += ": " + status.Error
		}
		return Result{Human: human, JSON: status}, nil
	})
}

func pkiInitHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "initialize workspace PKI"); err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		status, err := client.InitializePKI(ctx, scope, true)
		return Result{Human: "Workspace PKI initialized", JSON: status}, err
	})
}

func pkiBackendsHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKIBackends(ctx)
		return Result{Human: formatPKIBackends(values), JSON: values}, err
	})
}

func pkiProfilesHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKIProfiles(ctx)
		return Result{Human: formatPKIProfiles(values), JSON: values}, err
	})
}

func pkiAuthoritiesHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKIAuthorities(ctx)
		return Result{Human: formatPKIAuthorities(values), JSON: values}, err
	})
}

func pkiAuthorityInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKIAuthority(ctx, id)
		return Result{Human: fmt.Sprintf("%s %s %s", value.Authority.ID, value.Authority.Role, value.Authority.State), JSON: value}, err
	})
}

func pkiAuthorityCreateHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "create certificate authority"); err != nil {
			return Result{}, err
		}
		role := domainpki.AuthorityRole(invocation.Option("role"))
		if role == "" {
			role = domainpki.AuthorityRoleRoot
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.CreatePKIAuthority(ctx, scope, apppki.CreateAuthorityRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), Name: invocation.Positional("name"), Role: role,
			ParentAuthorityID: domainpki.AuthorityID(invocation.Option("parent")), ProfileID: domainpki.ProfileID(invocation.Option("profile")), BackendID: domainpki.BackendID(invocation.Option("backend")),
		})
		return Result{Human: fmt.Sprintf("Created %s authority %s", value.Authority.Role, value.Authority.ID), JSON: value}, err
	})
}

func pkiAuthorityUnlockHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if !invocation.Flag("approve") {
			return Result{}, errors.New("authority unlock requires --approve")
		}
		id, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		var duration time.Duration
		if raw := strings.TrimSpace(invocation.Option("duration")); raw != "" {
			duration, err = time.ParseDuration(raw)
			if err != nil {
				return Result{}, fmt.Errorf("parse signing lease duration: %w", err)
			}
		}
		scope, err := pkiScope(invocation, true)
		if err != nil {
			return Result{}, err
		}
		lease, err := client.UnlockPKIAuthority(ctx, scope, id, duration)
		return Result{Human: fmt.Sprintf("Authority %s unlocked until %s", id, lease.ExpiresAt.Format(time.RFC3339)), JSON: lease}, err
	})
}

func pkiAuthorityLockHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		if err := client.LockPKIAuthority(ctx, scope, id); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Authority %s locked", id), JSON: map[string]string{"authorityId": string(id), "state": "locked"}}, nil
	})
}

func pkiCertificatesHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKICertificates(ctx)
		return Result{Human: formatPKICertificates(values), JSON: values}, err
	})
}

func pkiCertificateInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKICertificate(ctx, id)
		return Result{Human: fmt.Sprintf("%s %s expires %s", value.ID, value.Purpose, value.Template.NotAfter.Format(time.RFC3339)), JSON: value}, err
	})
}

func pkiCertificateIssueHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "issue certificate"); err != nil {
			return Result{}, err
		}
		issuer, err := domainpki.NewAuthorityID(invocation.Option("issuer"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.IssuePKICertificate(ctx, scope, apppki.IssueCertificateRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), IssuerAuthorityID: issuer, Name: invocation.Positional("name"),
			ProfileID: domainpki.ProfileID(invocation.Option("profile")), BackendID: domainpki.BackendID(invocation.Option("backend")),
		})
		return Result{Human: fmt.Sprintf("Issued certificate generation %s", value.ID), JSON: value}, err
	})
}

func pkiCertificateRenewHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "renew certificate with its existing key"); err != nil {
			return Result{}, err
		}
		sourceID, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.RenewPKICertificate(ctx, scope, apppki.RenewCertificateRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), SourceGenerationID: sourceID,
			GenerationID: domainpki.GenerationID(invocation.Option("generation-id")),
		})
		return Result{Human: fmt.Sprintf("Renewed certificate as generation %s with key %s", value.Generation.ID, value.Generation.KeyID), JSON: value}, err
	})
}

func pkiCertificateRotateHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "rotate certificate onto a new key"); err != nil {
			return Result{}, err
		}
		sourceID, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.RotatePKICertificate(ctx, scope, apppki.RotateCertificateRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), SourceGenerationID: sourceID,
			GenerationID: domainpki.GenerationID(invocation.Option("generation-id")),
			KeyID:        domainpki.KeyID(invocation.Option("key-id")), BackendID: domainpki.BackendID(invocation.Option("backend")),
		})
		return Result{Human: fmt.Sprintf("Rotated certificate as generation %s with new key %s", value.Generation.ID, value.Generation.KeyID), JSON: value}, err
	})
}

func pkiCertificateRevokeHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "revoke certificate generation"); err != nil {
			return Result{}, err
		}
		generationID, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		reason := domainpki.RevocationReason(invocation.Option("reason"))
		if reason == "" {
			reason = domainpki.RevocationReasonUnspecified
		}
		if err := reason.Validate(); err != nil {
			return Result{}, err
		}
		var effectiveAt time.Time
		if value := invocation.Option("effective-at"); value != "" {
			effectiveAt, err = time.Parse(time.RFC3339, value)
			if err != nil {
				return Result{}, fmt.Errorf("parse effective revocation time: %w", err)
			}
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.RevokePKICertificate(ctx, scope, apppki.RevokeCertificateRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), GenerationID: generationID,
			Reason: reason, EffectiveAt: effectiveAt,
		})
		return Result{
			Human: fmt.Sprintf("Revoked certificate generation %s (%s); %d assignments affected", generationID, reason, len(value.AffectedAssignments)),
			JSON:  value,
		}, err
	})
}

func pkiRevocationsHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		values, err := client.ListPKIRevocations(ctx, id)
		return Result{Human: formatPKIRevocations(values), JSON: values}, err
	})
}

func pkiRevocationInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewRevocationID(invocation.Positional("revocation"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKIRevocation(ctx, id)
		return Result{Human: formatPKIRevocation(value), JSON: value}, err
	})
}

func pkiGenerationRevocationInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKIGenerationRevocation(ctx, id)
		return Result{Human: formatPKIRevocation(value), JSON: value}, err
	})
}

func pkiCRLPublishHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "publish certificate revocation list"); err != nil {
			return Result{}, err
		}
		authorityID, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		var validitySeconds uint32
		if value := invocation.Option("valid-for"); value != "" {
			validity, parseErr := time.ParseDuration(value)
			if parseErr != nil {
				return Result{}, fmt.Errorf("parse CRL validity: %w", parseErr)
			}
			if validity <= 0 || validity%time.Second != 0 || validity/time.Second > time.Duration(math.MaxUint32) {
				return Result{}, errors.New("CRL validity must be a positive whole number of seconds within uint32 range")
			}
			validitySeconds = uint32(validity / time.Second)
		}
		signatureAlgorithm := domainpki.SignatureAlgorithm(invocation.Option("signature-algorithm"))
		if signatureAlgorithm != "" && signatureAlgorithm != domainpki.SignatureAlgorithmAuto {
			if err := signatureAlgorithm.Validate(); err != nil {
				return Result{}, err
			}
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.PublishPKICRL(ctx, scope, apppki.PublishCRLRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), AuthorityID: authorityID,
			IssuerGenerationID: domainpki.GenerationID(invocation.Option("issuer-generation")),
			ValiditySeconds:    validitySeconds,
			SignatureAlgorithm: signatureAlgorithm,
		})
		return Result{
			Human: fmt.Sprintf("Published CRL %s number %d with %d revocations", value.Generation.ID, value.Generation.Number, len(value.Generation.RevocationIDs)),
			JSON:  value,
		}, err
	})
}

func pkiCRLsHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewAuthorityID(invocation.Positional("authority"))
		if err != nil {
			return Result{}, err
		}
		values, err := client.ListPKICRLs(ctx, id)
		return Result{Human: formatPKICRLs(values), JSON: values}, err
	})
}

func pkiCRLInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewCRLGenerationID(invocation.Positional("crl"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKICRL(ctx, id)
		return Result{Human: formatPKICRL(value), JSON: value}, err
	})
}

func pkiAssignmentsHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKIAssignments(ctx)
		return Result{Human: formatPKIAssignments(values), JSON: values}, err
	})
}

func pkiAssignmentInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewAssignmentID(invocation.Positional("assignment"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKIAssignment(ctx, id)
		return Result{Human: fmt.Sprintf("%s %s revision %d", value.Assignment.ID, value.Assignment.State, value.Assignment.Revision), JSON: value}, err
	})
}

func pkiAssignmentBindHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "bind PKI assignment"); err != nil {
			return Result{}, err
		}
		consumerID, err := domainpki.NewConsumerID(invocation.Positional("consumer"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.BindPKIAssignment(ctx, scope, apppki.BindAssignmentRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName),
			ID:             domainpki.AssignmentID(invocation.Option("id")), Purpose: domainpki.Purpose(invocation.Option("purpose")),
			ConsumerType: domainpki.ConsumerType(invocation.Option("consumer-type")), ConsumerID: consumerID,
			ProfileID: domainpki.ProfileID(invocation.Option("profile")), TrustSetID: domainpki.TrustSetID(invocation.Option("trust-set")),
			RotationPolicyID: domainpki.RotationPolicyID(invocation.Option("rotation-policy")),
		})
		return Result{Human: fmt.Sprintf("Bound assignment %s to %s", value.ID, value.ConsumerID), JSON: value}, err
	})
}

func pkiAssignmentStageHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "stage PKI assignment generation"); err != nil {
			return Result{}, err
		}
		assignmentID, err := domainpki.NewAssignmentID(invocation.Positional("assignment"))
		if err != nil {
			return Result{}, err
		}
		generationID, err := domainpki.NewGenerationID(invocation.Positional("generation"))
		if err != nil {
			return Result{}, err
		}
		revision, err := parsePKIRevision(invocation.Option("revision"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.StagePKIAssignment(ctx, scope, apppki.StageAssignmentRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), AssignmentID: assignmentID,
			GenerationID: generationID, ExpectedRevision: revision,
		})
		return Result{Human: fmt.Sprintf("Staged generation %s on assignment %s", generationID, assignmentID), JSON: value}, err
	})
}

func pkiAssignmentActivateHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "activate PKI assignment generation"); err != nil {
			return Result{}, err
		}
		id, err := domainpki.NewAssignmentID(invocation.Positional("assignment"))
		if err != nil {
			return Result{}, err
		}
		revision, err := parsePKIRevision(invocation.Option("revision"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.ActivatePKIAssignment(ctx, scope, apppki.ActivateAssignmentRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), AssignmentID: id, ExpectedRevision: revision,
		})
		return Result{Human: fmt.Sprintf("Activated assignment %s", id), JSON: value}, err
	})
}

func pkiAssignmentUnbindHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "retire PKI assignment"); err != nil {
			return Result{}, err
		}
		id, err := domainpki.NewAssignmentID(invocation.Positional("assignment"))
		if err != nil {
			return Result{}, err
		}
		revision, err := parsePKIRevision(invocation.Option("revision"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.UnbindPKIAssignment(ctx, scope, apppki.UnbindAssignmentRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), AssignmentID: id, ExpectedRevision: revision,
		})
		return Result{Human: fmt.Sprintf("Retired assignment %s", id), JSON: value}, err
	})
}

func pkiTrustSetsHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, _ Invocation, client PKIControlClient) (Result, error) {
		values, err := client.ListPKITrustSets(ctx)
		return Result{Human: formatPKITrustSets(values), JSON: values}, err
	})
}

func pkiTrustSetInspectHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		id, err := domainpki.NewTrustSetID(invocation.Positional("trust-set"))
		if err != nil {
			return Result{}, err
		}
		value, err := client.InspectPKITrustSet(ctx, id)
		return Result{Human: fmt.Sprintf("%s %s revision %d", value.TrustSet.ID, value.TrustSet.State, value.TrustSet.Revision), JSON: value}, err
	})
}

func pkiTrustSetCreateHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "create PKI trust set"); err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.CreatePKITrustSet(ctx, scope, apppki.CreateTrustSetRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName),
			ID:             domainpki.TrustSetID(invocation.Option("id")), Name: invocation.Positional("name"),
		})
		return Result{Human: fmt.Sprintf("Created trust set %s", value.ID), JSON: value}, err
	})
}

func pkiTrustSetStageHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "stage PKI trust generation"); err != nil {
			return Result{}, err
		}
		id, err := domainpki.NewTrustSetID(invocation.Positional("trust-set"))
		if err != nil {
			return Result{}, err
		}
		revision, err := parsePKIRevision(invocation.Option("revision"))
		if err != nil {
			return Result{}, err
		}
		anchors, err := parseGenerationIDs(invocation.Option("anchors"), true)
		if err != nil {
			return Result{}, err
		}
		intermediates, err := parseGenerationIDs(invocation.Option("intermediates"), false)
		if err != nil {
			return Result{}, err
		}
		crls, err := parseCRLGenerationIDs(invocation.Option("crls"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.StagePKITrustSet(ctx, scope, apppki.StageTrustSetRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), TrustSetID: id, ExpectedRevision: revision,
			GenerationID:        domainpki.TrustSetGenerationID(invocation.Option("generation-id")),
			AnchorGenerationIDs: anchors, IntermediateGenerationIDs: intermediates, CRLGenerationIDs: crls,
		})
		return Result{Human: fmt.Sprintf("Staged trust generation on %s", id), JSON: value}, err
	})
}

func pkiTrustSetActivateHandler(runtime Runtime) Handler {
	return withPKIClient(runtime, func(ctx context.Context, invocation Invocation, client PKIControlClient) (Result, error) {
		if err := confirmPKIMutation(ctx, invocation, "activate PKI trust generation"); err != nil {
			return Result{}, err
		}
		id, err := domainpki.NewTrustSetID(invocation.Positional("trust-set"))
		if err != nil {
			return Result{}, err
		}
		revision, err := parsePKIRevision(invocation.Option("revision"))
		if err != nil {
			return Result{}, err
		}
		scope, err := pkiScope(invocation, false)
		if err != nil {
			return Result{}, err
		}
		value, err := client.ActivatePKITrustSet(ctx, scope, apppki.ActivateTrustSetRequest{
			IdempotencyKey: invocation.Option(pkiIdempotencyKeyOptionName), TrustSetID: id, ExpectedRevision: revision,
		})
		return Result{Human: fmt.Sprintf("Activated trust set %s", id), JSON: value}, err
	})
}

func parsePKIRevision(value string) (uint64, error) {
	revision, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil || revision == 0 {
		return 0, errors.New("pki revision must be a positive integer")
	}
	return revision, nil
}

func parseGenerationIDs(value string, required bool) ([]domainpki.GenerationID, error) {
	parts := splitPKIList(value)
	if required && len(parts) == 0 {
		return nil, errors.New("at least one trust anchor generation is required")
	}
	result := make([]domainpki.GenerationID, 0, len(parts))
	for _, part := range parts {
		id, err := domainpki.NewGenerationID(part)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func parseCRLGenerationIDs(value string) ([]domainpki.CRLGenerationID, error) {
	parts := splitPKIList(value)
	result := make([]domainpki.CRLGenerationID, 0, len(parts))
	for _, part := range parts {
		id, err := domainpki.NewCRLGenerationID(part)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func splitPKIList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func formatPKIBackends(values []domainpki.BackendDescriptor) string {
	if len(values) == 0 {
		return "No PKI backends available"
	}
	lines := []string{"ID VERSION KEYS"}
	for _, value := range values {
		algorithms := make([]string, len(value.KeyAlgorithms))
		for index, algorithm := range value.KeyAlgorithms {
			algorithms[index] = string(algorithm)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", value.ID, value.Version, strings.Join(algorithms, ",")))
	}
	return strings.Join(lines, "\n")
}

func formatPKIProfiles(values []domainpki.Profile) string {
	if len(values) == 0 {
		return "No PKI profiles available"
	}
	lines := []string{"ID PURPOSE BACKEND COMPATIBILITY"}
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", value.ID, value.Purpose, value.Backend, value.Compatibility))
	}
	return strings.Join(lines, "\n")
}

func formatPKIAuthorities(values []domainpki.Authority) string {
	if len(values) == 0 {
		return "No certificate authorities"
	}
	lines := []string{"ID ROLE STATE NAME"}
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", value.ID, value.Role, value.State, value.Name))
	}
	return strings.Join(lines, "\n")
}

func formatPKICertificates(values []domainpki.CertificateGeneration) string {
	if len(values) == 0 {
		return "No certificate generations"
	}
	lines := []string{"ID PURPOSE STATE EXPIRES"}
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", value.ID, value.Purpose, value.State, value.Template.NotAfter.Format(time.RFC3339)))
	}
	return strings.Join(lines, "\n")
}

func formatPKIRevocations(values []domainpki.Revocation) string {
	if len(values) == 0 {
		return "No certificate revocations"
	}
	lines := make([]string, len(values))
	for index, value := range values {
		lines[index] = formatPKIRevocation(value)
	}
	return strings.Join(lines, "\n")
}

func formatPKIRevocation(value domainpki.Revocation) string {
	return fmt.Sprintf(
		"%s generation=%s reason=%s effective=%s",
		value.ID, value.GenerationID, value.Reason, value.EffectiveAt.Format(time.RFC3339),
	)
}

func formatPKICRLs(values []domainpki.CRLGeneration) string {
	if len(values) == 0 {
		return "No CRL generations."
	}
	lines := make([]string, len(values))
	for index, value := range values {
		lines[index] = formatPKICRL(value)
	}
	return strings.Join(lines, "\n")
}

func formatPKICRL(value domainpki.CRLGeneration) string {
	return fmt.Sprintf("%s number=%d issuer=%s revocations=%d valid-until=%s", value.ID, value.Number,
		value.IssuerGenerationID, len(value.RevocationIDs), value.NextUpdate.Format(time.RFC3339))
}

func formatPKIAssignments(values []domainpki.Assignment) string {
	if len(values) == 0 {
		return "No PKI assignments"
	}
	lines := []string{"ID CONSUMER PURPOSE STATE REVISION"}
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("%s %s:%s %s %s %d", value.ID, value.ConsumerType, value.ConsumerID, value.Purpose, value.State, value.Revision))
	}
	return strings.Join(lines, "\n")
}

func formatPKITrustSets(values []domainpki.TrustSet) string {
	if len(values) == 0 {
		return "No PKI trust sets"
	}
	lines := []string{"ID STATE REVISION NAME"}
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("%s %s %d %s", value.ID, value.State, value.Revision, value.Name))
	}
	return strings.Join(lines, "\n")
}
