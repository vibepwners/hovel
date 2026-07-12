package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	CredentialExecutionSchemaV1            = "hovel.pki.credential-execution/v1"
	MaximumCredentialExecutionLedgerJSON   = 1 << 20
	MaximumCredentialExecutionFailureBytes = 1024
)

// CredentialExecutionKind identifies one non-stamp provider invocation.
type CredentialExecutionKind string

const (
	CredentialExecutionRuntime  CredentialExecutionKind = "runtime"
	CredentialExecutionFiles    CredentialExecutionKind = "files"
	CredentialExecutionEncoding CredentialExecutionKind = "provider-encoding"
)

func (k CredentialExecutionKind) Validate() error {
	switch k {
	case CredentialExecutionRuntime, CredentialExecutionFiles, CredentialExecutionEncoding:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential execution kind %q", k)
	}
}

type CredentialExecutionStatus string

const (
	CredentialExecutionPending   CredentialExecutionStatus = "pending"
	CredentialExecutionSucceeded CredentialExecutionStatus = "succeeded"
	CredentialExecutionFailed    CredentialExecutionStatus = "failed"
)

func (s CredentialExecutionStatus) Validate() error {
	switch s {
	case CredentialExecutionPending, CredentialExecutionSucceeded, CredentialExecutionFailed:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential execution status %q", s)
	}
}

// CredentialExecutionMaterial is deliberately incapable of storing material
// bytes, provider references, or protected paths.
type CredentialExecutionMaterial struct {
	Projection CredentialProjection   `json:"projection"`
	Form       CredentialMaterialForm `json:"form"`
	Encoding   string                 `json:"encoding"`
	MediaType  string                 `json:"mediaType,omitempty"`
	SHA256     string                 `json:"sha256"`
	Size       uint64                 `json:"size"`
}

func (m *CredentialExecutionMaterial) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("pki: credential execution material destination is nil")
	}
	type wire CredentialExecutionMaterial
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionLedgerJSON, &value, "credential execution material",
	); err != nil {
		return err
	}
	material := CredentialExecutionMaterial(value)
	if err := material.Validate(); err != nil {
		return err
	}
	*m = material
	return nil
}

func (m CredentialExecutionMaterial) Validate() error {
	if err := m.Projection.Validate(); err != nil {
		return err
	}
	if err := m.Form.Validate(); err != nil {
		return err
	}
	if err := validateResolvedProjectionForm(m.Projection, m.Form); err != nil {
		return err
	}
	if err := validateCanonicalContractText(
		m.Encoding, "credential execution material encoding", MaximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	if m.MediaType != "" {
		if err := validateCanonicalContractText(
			m.MediaType, "credential execution material media type", MaxNameLength,
		); err != nil {
			return err
		}
	}
	if err := validateCanonicalSHA256(m.SHA256, "credential execution material"); err != nil {
		return err
	}
	if m.Form == CredentialMaterialPrivateReference {
		if m.Size != 0 {
			return errors.New("pki: reference credential execution material must have zero size")
		}
		return nil
	}
	if m.Size == 0 || m.Size > MaximumBundleBinaryBytes {
		return errors.New("pki: byte credential execution material size is invalid")
	}
	return nil
}

// CredentialExecutionPlan is the non-secret projection of one validated
// provider request. Credential is present only for runtime/files delivery;
// provider schema fields are present only for encoding.
type CredentialExecutionPlan struct {
	Kind                CredentialExecutionKind       `json:"kind"`
	Provider            CredentialProviderTarget      `json:"provider"`
	AssignmentID        AssignmentID                  `json:"assignmentId,omitempty"`
	SlotName            CredentialSlotName            `json:"slotName,omitempty"`
	Credential          *ResolvedCredentialMetadata   `json:"credential,omitempty"`
	Materials           []CredentialExecutionMaterial `json:"materials"`
	Scope               CredentialOperationScope      `json:"scope"`
	ProviderSchema      string                        `json:"providerSchema,omitempty"`
	OutputForm          CredentialMaterialForm        `json:"outputForm,omitempty"`
	MaximumEncodedBytes uint64                        `json:"maximumEncodedBytes,omitempty"`
}

func (p *CredentialExecutionPlan) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("pki: credential execution plan destination is nil")
	}
	type wire CredentialExecutionPlan
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionLedgerJSON, &value, "credential execution plan",
	); err != nil {
		return err
	}
	plan := CredentialExecutionPlan(value)
	if err := plan.Validate(); err != nil {
		return err
	}
	*p = plan.Clone()
	return nil
}

func (p CredentialExecutionPlan) Clone() CredentialExecutionPlan {
	result := p
	if p.Credential != nil {
		credential := *p.Credential
		result.Credential = &credential
	}
	result.Materials = append([]CredentialExecutionMaterial(nil), p.Materials...)
	return result
}

func (p CredentialExecutionPlan) Validate() error {
	if err := p.Kind.Validate(); err != nil {
		return err
	}
	if err := p.Provider.Validate(); err != nil {
		return err
	}
	if err := p.Scope.Validate(); err != nil {
		return err
	}
	if len(p.Materials) == 0 || len(p.Materials) > MaximumCredentialExecutionFiles {
		return errors.New("pki: credential execution materials are empty or exceed limits")
	}
	for _, material := range p.Materials {
		if err := material.Validate(); err != nil {
			return err
		}
	}
	switch p.Kind {
	case CredentialExecutionRuntime:
		if len(p.Materials) != 1 || p.Materials[0].MediaType != "" {
			return errors.New("pki: runtime credential execution requires one non-file material")
		}
		return p.validateDeliveryFields()
	case CredentialExecutionFiles:
		for _, material := range p.Materials {
			if material.MediaType == "" || material.Form == CredentialMaterialPrivateReference {
				return errors.New("pki: files credential execution requires byte materials with media types")
			}
		}
		return p.validateDeliveryFields()
	case CredentialExecutionEncoding:
		if len(p.Materials) != 1 || p.Materials[0].MediaType != "" ||
			p.AssignmentID != "" || p.SlotName != "" || p.Credential != nil {
			return errors.New("pki: encoding credential execution delivery fields are invalid")
		}
		if err := validateCanonicalContractText(
			p.ProviderSchema, "credential provider schema", MaxIDLength,
		); err != nil {
			return err
		}
		if err := p.OutputForm.Validate(); err != nil {
			return err
		}
		if p.MaximumEncodedBytes == 0 || p.MaximumEncodedBytes > MaximumBundleBinaryBytes {
			return errors.New("pki: credential execution encoding bound is invalid")
		}
	}
	return nil
}

func (p CredentialExecutionPlan) validateDeliveryFields() error {
	if err := p.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := p.SlotName.Validate(); err != nil {
		return err
	}
	if p.Credential == nil {
		return errors.New("pki: credential execution metadata is required")
	}
	if err := p.Credential.Validate(); err != nil {
		return err
	}
	if p.ProviderSchema != "" || p.OutputForm != "" || p.MaximumEncodedBytes != 0 {
		return errors.New("pki: credential delivery execution contains encoding fields")
	}
	return nil
}

type CredentialExecutionOutput struct {
	Form     CredentialMaterialForm `json:"form"`
	Encoding string                 `json:"encoding"`
	SHA256   string                 `json:"sha256"`
	Size     uint64                 `json:"size"`
}

func (o *CredentialExecutionOutput) UnmarshalJSON(data []byte) error {
	if o == nil {
		return errors.New("pki: credential execution output destination is nil")
	}
	type wire CredentialExecutionOutput
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionLedgerJSON, &value, "credential execution output",
	); err != nil {
		return err
	}
	output := CredentialExecutionOutput(value)
	if err := output.validateShape(); err != nil {
		return err
	}
	*o = output
	return nil
}

func (o CredentialExecutionOutput) validateShape() error {
	if err := o.Form.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalContractText(
		o.Encoding, "credential execution output encoding", MaximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	if err := validateCanonicalSHA256(o.SHA256, "credential execution output"); err != nil {
		return err
	}
	if o.Size == 0 || o.Size > MaximumBundleBinaryBytes {
		return errors.New("pki: credential execution output size is invalid")
	}
	return nil
}

func (o CredentialExecutionOutput) Validate(plan CredentialExecutionPlan) error {
	if plan.Kind != CredentialExecutionEncoding {
		return errors.New("pki: credential execution output requires an encoding plan")
	}
	if err := o.validateShape(); err != nil {
		return err
	}
	if o.Form != plan.OutputForm {
		return errors.New("pki: credential execution output form does not match its plan")
	}
	if o.Size > plan.MaximumEncodedBytes {
		return errors.New("pki: credential execution output size exceeds its plan")
	}
	return nil
}

// CredentialExecutionResult contains only non-secret receipt hashes or encoded
// output metadata. ProviderReferenceSHA256 is a hash of any opaque provider
// reference; the reference itself is never persisted.
type CredentialExecutionResult struct {
	ProviderReferenceSHA256 string                     `json:"providerReferenceSha256,omitempty"`
	ReceiptSHA256           string                     `json:"receiptSha256,omitempty"`
	Output                  *CredentialExecutionOutput `json:"output,omitempty"`
}

func (r *CredentialExecutionResult) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential execution result destination is nil")
	}
	type wire CredentialExecutionResult
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionLedgerJSON, &value, "credential execution result",
	); err != nil {
		return err
	}
	result := CredentialExecutionResult(value)
	if result.ProviderReferenceSHA256 != "" {
		if err := validateCanonicalSHA256(
			result.ProviderReferenceSHA256, "credential execution provider reference",
		); err != nil {
			return err
		}
	}
	if result.ReceiptSHA256 != "" {
		if err := validateCanonicalSHA256(result.ReceiptSHA256, "credential execution receipt"); err != nil {
			return err
		}
	}
	*r = result.Clone()
	return nil
}

func (r CredentialExecutionResult) Clone() CredentialExecutionResult {
	result := r
	if r.Output != nil {
		output := *r.Output
		result.Output = &output
	}
	return result
}

func (r CredentialExecutionResult) Validate(plan CredentialExecutionPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Kind == CredentialExecutionEncoding {
		if r.ProviderReferenceSHA256 != "" || r.ReceiptSHA256 != "" || r.Output == nil {
			return errors.New("pki: encoding credential execution result is invalid")
		}
		return r.Output.Validate(plan)
	}
	if r.Output != nil {
		return errors.New("pki: delivery credential execution result contains encoded output")
	}
	if r.ProviderReferenceSHA256 != "" {
		if err := validateCanonicalSHA256(
			r.ProviderReferenceSHA256, "credential execution provider reference",
		); err != nil {
			return err
		}
	}
	if r.ReceiptSHA256 != "" {
		return validateCanonicalSHA256(r.ReceiptSHA256, "credential execution receipt")
	}
	return nil
}

type CredentialExecution struct {
	SchemaVersion string                       `json:"schemaVersion"`
	ID            CredentialExecutionRequestID `json:"id"`
	Plan          CredentialExecutionPlan      `json:"plan"`
	Status        CredentialExecutionStatus    `json:"status"`
	Result        *CredentialExecutionResult   `json:"result,omitempty"`
	Failure       string                       `json:"failure,omitempty"`
	Revision      uint64                       `json:"revision"`
	CreatedAt     time.Time                    `json:"createdAt"`
	UpdatedAt     time.Time                    `json:"updatedAt"`
}

type credentialExecutionWire CredentialExecution

func (e *CredentialExecution) UnmarshalJSON(data []byte) error {
	if e == nil {
		return errors.New("pki: credential execution destination is nil")
	}
	var wire credentialExecutionWire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionLedgerJSON, &wire, "credential execution",
	); err != nil {
		return err
	}
	execution := CredentialExecution(wire)
	allowed := []string(nil)
	switch execution.Status {
	case CredentialExecutionPending:
	case CredentialExecutionSucceeded:
		allowed = []string{"result"}
	case CredentialExecutionFailed:
		allowed = []string{"failure"}
	default:
		return fmt.Errorf("pki: unsupported credential execution status %q", execution.Status)
	}
	if err := rejectDisallowedVariantJSONFields(
		data, allowed, []string{"result", "failure"}, "credential execution",
	); err != nil {
		return err
	}
	if err := execution.Validate(); err != nil {
		return err
	}
	*e = execution.Clone()
	return nil
}

func (e CredentialExecution) Clone() CredentialExecution {
	result := e
	result.Plan = e.Plan.Clone()
	if e.Result != nil {
		value := e.Result.Clone()
		result.Result = &value
	}
	return result
}

func (e CredentialExecution) Validate() error {
	if err := validateSchemaVersion(e.SchemaVersion, CredentialExecutionSchemaV1); err != nil {
		return err
	}
	if err := e.ID.Validate(); err != nil {
		return err
	}
	if err := e.Plan.Validate(); err != nil {
		return err
	}
	if err := e.Status.Validate(); err != nil {
		return err
	}
	if err := validateSequenceNumber(e.Revision, "credential execution revision"); err != nil {
		return err
	}
	if !validCredentialBookkeepingTimestamp(e.CreatedAt) ||
		!validCredentialBookkeepingTimestamp(e.UpdatedAt) || e.UpdatedAt.Before(e.CreatedAt) {
		return errors.New("pki: credential execution timestamps are invalid or noncanonical")
	}
	switch e.Status {
	case CredentialExecutionPending:
		if e.Result != nil || e.Failure != "" {
			return errors.New("pki: pending credential execution contains terminal state")
		}
	case CredentialExecutionSucceeded:
		if e.Result == nil || e.Failure != "" {
			return errors.New("pki: succeeded credential execution state is invalid")
		}
		return e.Result.Validate(e.Plan)
	case CredentialExecutionFailed:
		failure := strings.TrimSpace(e.Failure)
		if failure == "" || failure != e.Failure || len(failure) > MaximumCredentialExecutionFailureBytes || e.Result != nil {
			return errors.New("pki: failed credential execution state is invalid")
		}
	}
	return nil
}

func NewRuntimeCredentialExecution(
	request CredentialRuntimeRequest,
	createdAt time.Time,
) (CredentialExecution, error) {
	if err := request.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	credential := request.Credential
	return newCredentialExecution(request.RequestID, CredentialExecutionPlan{
		Kind: CredentialExecutionRuntime, Provider: request.Provider,
		AssignmentID: request.AssignmentID, SlotName: request.SlotName,
		Credential: &credential,
		Materials:  []CredentialExecutionMaterial{executionMaterialFromResolved(request.Material)},
		Scope:      request.Scope,
	}, createdAt)
}

func NewFilesCredentialExecution(
	request CredentialFilesRequest,
	createdAt time.Time,
) (CredentialExecution, error) {
	if err := request.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	credential := request.Credential
	materials := make([]CredentialExecutionMaterial, len(request.Files))
	for index, file := range request.Files {
		materials[index] = CredentialExecutionMaterial{
			Projection: file.Projection, Form: file.Form, Encoding: file.MediaType,
			MediaType: file.MediaType, SHA256: file.SHA256, Size: file.Size,
		}
	}
	return newCredentialExecution(request.RequestID, CredentialExecutionPlan{
		Kind: CredentialExecutionFiles, Provider: request.Provider,
		AssignmentID: request.AssignmentID, SlotName: request.SlotName,
		Credential: &credential, Materials: materials, Scope: request.Scope,
	}, createdAt)
}

func NewEncodingCredentialExecution(
	request CredentialEncodingRequest,
	createdAt time.Time,
) (CredentialExecution, error) {
	if err := request.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	return newCredentialExecution(request.RequestID, CredentialExecutionPlan{
		Kind: CredentialExecutionEncoding, Provider: request.Provider,
		Materials: []CredentialExecutionMaterial{executionMaterialFromResolved(request.Source)},
		Scope:     request.Scope, ProviderSchema: request.ProviderSchema,
		OutputForm: request.OutputForm, MaximumEncodedBytes: request.MaximumEncodedBytes,
	}, createdAt)
}

func executionMaterialFromResolved(material ResolvedCredentialMaterial) CredentialExecutionMaterial {
	return CredentialExecutionMaterial{
		Projection: material.Projection, Form: material.Form, Encoding: material.Encoding,
		SHA256: material.SHA256, Size: uint64(len(material.Data)),
	}
}

func newCredentialExecution(
	id CredentialExecutionRequestID,
	plan CredentialExecutionPlan,
	createdAt time.Time,
) (CredentialExecution, error) {
	execution := CredentialExecution{
		SchemaVersion: CredentialExecutionSchemaV1, ID: id, Plan: plan.Clone(),
		Status: CredentialExecutionPending, Revision: 1,
		CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC(),
	}
	if err := execution.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	return execution.Clone(), nil
}

func CompleteCredentialDeliveryExecution(
	execution CredentialExecution,
	receipt CredentialDeliveryReceipt,
	updatedAt time.Time,
) (CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	if execution.Plan.Kind == CredentialExecutionEncoding {
		return CredentialExecution{}, errors.New("pki: encoding execution cannot complete with a delivery receipt")
	}
	if err := receipt.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	if receipt.RequestID != execution.ID {
		return CredentialExecution{}, errors.New("pki: credential delivery receipt id does not match its execution")
	}
	result := CredentialExecutionResult{ReceiptSHA256: receipt.ReceiptSHA256}
	if receipt.ProviderReference != "" {
		digest := sha256.Sum256([]byte(receipt.ProviderReference))
		result.ProviderReferenceSHA256 = hex.EncodeToString(digest[:])
	}
	return completeCredentialExecution(execution, result, updatedAt)
}

func CompleteCredentialEncodingExecution(
	execution CredentialExecution,
	encoded CredentialEncodingResult,
	updatedAt time.Time,
) (CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	if execution.Plan.Kind != CredentialExecutionEncoding {
		return CredentialExecution{}, errors.New("pki: delivery execution cannot complete with encoded material")
	}
	if err := encoded.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	if encoded.RequestID != execution.ID || encoded.Form != execution.Plan.OutputForm ||
		uint64(len(encoded.Data)) > execution.Plan.MaximumEncodedBytes {
		return CredentialExecution{}, errors.New("pki: encoded material does not match its execution plan")
	}
	output := CredentialExecutionOutput{
		Form: encoded.Form, Encoding: encoded.Encoding, SHA256: encoded.SHA256,
		Size: uint64(len(encoded.Data)),
	}
	return completeCredentialExecution(
		execution, CredentialExecutionResult{Output: &output}, updatedAt,
	)
}

func completeCredentialExecution(
	execution CredentialExecution,
	result CredentialExecutionResult,
	updatedAt time.Time,
) (CredentialExecution, error) {
	if execution.Status != CredentialExecutionPending {
		return CredentialExecution{}, errors.New("pki: only a pending credential execution can succeed")
	}
	next, err := nextCredentialExecutionRevision(execution, updatedAt)
	if err != nil {
		return CredentialExecution{}, err
	}
	validated := result.Clone()
	if err := validated.Validate(execution.Plan); err != nil {
		return CredentialExecution{}, err
	}
	next.Status = CredentialExecutionSucceeded
	next.Result = &validated
	if err := next.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	return next.Clone(), nil
}

func FailCredentialExecution(
	execution CredentialExecution,
	failure string,
	updatedAt time.Time,
) (CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	if execution.Status != CredentialExecutionPending {
		return CredentialExecution{}, errors.New("pki: only a pending credential execution can fail")
	}
	next, err := nextCredentialExecutionRevision(execution, updatedAt)
	if err != nil {
		return CredentialExecution{}, err
	}
	next.Status = CredentialExecutionFailed
	next.Failure = strings.TrimSpace(failure)
	if err := next.Validate(); err != nil {
		return CredentialExecution{}, err
	}
	return next.Clone(), nil
}

func nextCredentialExecutionRevision(
	execution CredentialExecution,
	updatedAt time.Time,
) (CredentialExecution, error) {
	updatedAt = updatedAt.UTC()
	if updatedAt.Before(execution.UpdatedAt) {
		return CredentialExecution{}, errors.New("pki: credential execution update precedes its current state")
	}
	if execution.Revision == MaximumSequenceNumber {
		return CredentialExecution{}, errors.New("pki: credential execution revision is exhausted")
	}
	next := execution.Clone()
	next.Revision++
	next.UpdatedAt = updatedAt
	return next, nil
}

func ValidateCredentialExecutionTransition(previous, next CredentialExecution) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	var expected CredentialExecution
	var err error
	switch next.Status {
	case CredentialExecutionSucceeded:
		if next.Result == nil {
			return errors.New("pki: credential execution success is missing a result")
		}
		expected, err = completeCredentialExecution(previous, *next.Result, next.UpdatedAt)
	case CredentialExecutionFailed:
		expected, err = FailCredentialExecution(previous, next.Failure, next.UpdatedAt)
	default:
		return errors.New("pki: credential execution transition does not enter a terminal state")
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, next) {
		return errors.New("pki: credential execution transition changes immutable or derived state")
	}
	return nil
}

func ValidateCredentialExecutionAssignment(
	assignment Assignment,
	plan CredentialExecutionPlan,
) error {
	if err := assignment.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Kind == CredentialExecutionEncoding {
		return errors.New("pki: encoding credential execution has no assignment")
	}
	if plan.Credential == nil || assignment.ID != plan.AssignmentID ||
		assignment.Purpose != plan.Credential.Purpose ||
		assignment.ConsumerType != plan.Credential.ConsumerType ||
		assignment.ProfileID != plan.Credential.ProfileID {
		return errors.New("pki: credential execution plan does not match its assignment")
	}
	return validateCredentialAssignmentUsable(assignment, "credential execution")
}

// validateCredentialAssignmentUsable limits credential delivery to assignments
// that still have an operable active lineage. A degraded assignment remains
// usable because it retains an active certificate generation; pending,
// disabled, and retired assignments deliberately fail closed.
func validateCredentialAssignmentUsable(assignment Assignment, operation string) error {
	switch assignment.State {
	case AssignmentStateActive, AssignmentStateDegraded:
		return nil
	case AssignmentStatePending, AssignmentStateDisabled, AssignmentStateRetired:
		return fmt.Errorf("pki: %s assignment is not usable while %s", operation, assignment.State)
	default:
		return fmt.Errorf("pki: %s assignment has unsupported state %q", operation, assignment.State)
	}
}
