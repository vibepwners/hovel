package throwcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	operatordomain "github.com/Vibe-Pwners/hovel/internal/domain/operator"
)

const DefaultOperation = "default"

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

type PlanRepository interface {
	RecordPlan(context.Context, PlanRecord) error
	GetPlan(context.Context, string, string) (PlanRecord, bool, error)
}

type ConfirmationRepository interface {
	RecordConfirmation(context.Context, ConfirmationRecord) error
	GetConfirmation(context.Context, string, string) (ConfirmationRecord, bool, error)
}

type LaunchKeyGate interface {
	CreatePending(context.Context, PendingRequest) (PendingStatus, error)
	Confirm(context.Context, PendingConfirmation) (PendingStatus, error)
	RequireReady(context.Context, string) (PendingStatus, error)
}

type ServiceOptions struct {
	Plans         PlanRepository
	Confirmations ConfirmationRepository
	LaunchKeys    LaunchKeyGate
	Clock         Clock
}

type Service struct {
	plans         PlanRepository
	confirmations ConfirmationRepository
	launchKeys    LaunchKeyGate
	clock         Clock
}

func NewService(options ServiceOptions) Service {
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return Service{
		plans:         options.Plans,
		confirmations: options.Confirmations,
		launchKeys:    options.LaunchKeys,
		clock:         clock,
	}
}

type PlanRequest struct {
	Workspace      string
	Operation      string
	Chain          string
	Targets        []string
	Modules        []string
	ChainConfig    map[string]string
	TargetConfigs  map[string]map[string]string
	AllowDangerous bool
	NowBypass      bool
}

type PlanRecord struct {
	ID             string
	ConfirmationID string
	PlanHash       string
	Workspace      string
	Operation      string
	Chain          string
	Targets        []string
	Modules        []string
	ChainConfig    map[string]string
	TargetConfigs  map[string]map[string]string
	Flags          operatordomain.ApprovalFlags
	Review         string
	Intent         string
	CreatedAt      string
}

type PlanResult struct {
	Plan        PlanRecord
	Pending     PendingStatus
	NextActions []string
}

type ConfirmRequest struct {
	Workspace string
	PlanID    string
	PlanHash  string
	EntityID  string
	Method    string
}

type ConfirmationRecord struct {
	ID          string
	Workspace   string
	PlanID      string
	PlanHash    string
	EntityID    string
	Method      string
	ConfirmedAt string
}

type ConfirmResult struct {
	Plan         PlanRecord
	Confirmation ConfirmationRecord
	Pending      PendingStatus
	NextActions  []string
}

type StartRequest struct {
	Workspace string
	PlanID    string
}

type StartReadiness struct {
	Ready        bool
	Plan         PlanRecord
	Confirmation ConfirmationRecord
	Pending      PendingStatus
}

type PendingRequest struct {
	PendingID string
	Operation string
	PlanHash  string
	Flags     operatordomain.ApprovalFlags
}

type PendingConfirmation struct {
	PendingID   string
	EntityID    string
	PlanHash    string
	Flags       operatordomain.ApprovalFlags
	ConfirmedAt time.Time
}

type PendingStatus struct {
	ID                  string
	Ready               bool
	RequiredApproverIDs []string
	MissingApproverIDs  []string
}

func (s Service) BuildPlan(req PlanRequest) (PlanRecord, error) {
	req.Workspace = workspaceOrDefault(req.Workspace)
	req.Operation = operationOrDefault(req.Operation)
	req.Chain = strings.TrimSpace(req.Chain)
	if req.Chain == "" {
		return PlanRecord{}, errors.New("chain is required")
	}
	targets := cleanStrings(req.Targets)
	if len(targets) == 0 {
		return PlanRecord{}, errors.New("target is required")
	}
	modules := cleanStrings(req.Modules)
	chainConfig := cloneStringMap(req.ChainConfig)
	targetConfigs := cloneTargetConfigs(req.TargetConfigs)
	flags := operatordomain.ApprovalFlags{
		AllowDangerous: req.AllowDangerous,
		NowBypass:      req.NowBypass,
	}
	hash := planHash(planHashInput{
		Operation:     req.Operation,
		Chain:         req.Chain,
		Targets:       targets,
		Modules:       modules,
		ChainConfig:   chainConfig,
		TargetConfigs: targetConfigs,
		Flags:         flags,
	})
	now := s.now().UTC().Format(time.RFC3339Nano)
	return PlanRecord{
		ID:             "plan-" + stableIDComponent(hash),
		ConfirmationID: "confirmation-" + stableIDComponent(hash),
		PlanHash:       hash,
		Workspace:      req.Workspace,
		Operation:      req.Operation,
		Chain:          req.Chain,
		Targets:        targets,
		Modules:        modules,
		ChainConfig:    chainConfig,
		TargetConfigs:  targetConfigs,
		Flags:          flags,
		Review:         "operator-confirmed",
		Intent:         fmt.Sprintf("throw chain %s against %d target(s)", req.Chain, len(targets)),
		CreatedAt:      now,
	}, nil
}

func (s Service) Plan(ctx context.Context, req PlanRequest) (PlanResult, error) {
	if err := ctx.Err(); err != nil {
		return PlanResult{}, err
	}
	if s.plans == nil {
		return PlanResult{}, errors.New("throw plan repository is not configured")
	}
	plan, err := s.BuildPlan(req)
	if err != nil {
		return PlanResult{}, err
	}
	if err := s.plans.RecordPlan(ctx, plan); err != nil {
		return PlanResult{}, err
	}
	var pending PendingStatus
	if s.launchKeys != nil {
		pending, err = s.launchKeys.CreatePending(ctx, PendingRequest{
			PendingID: plan.ID,
			Operation: plan.Operation,
			PlanHash:  plan.PlanHash,
			Flags:     plan.Flags,
		})
		if err != nil {
			return PlanResult{}, err
		}
	}
	return PlanResult{
		Plan:        plan,
		Pending:     pending,
		NextActions: []string{"review_plan", "confirm_plan", "start_throw"},
	}, nil
}

func (s Service) Confirm(ctx context.Context, req ConfirmRequest) (ConfirmResult, error) {
	if err := ctx.Err(); err != nil {
		return ConfirmResult{}, err
	}
	if s.plans == nil {
		return ConfirmResult{}, errors.New("throw plan repository is not configured")
	}
	if s.confirmations == nil {
		return ConfirmResult{}, errors.New("throw confirmation repository is not configured")
	}
	workspace := workspaceOrDefault(req.Workspace)
	plan, ok, err := s.plans.GetPlan(ctx, workspace, strings.TrimSpace(req.PlanID))
	if err != nil {
		return ConfirmResult{}, err
	}
	if !ok {
		return ConfirmResult{}, fmt.Errorf("throw plan %s does not exist", strings.TrimSpace(req.PlanID))
	}
	if strings.TrimSpace(req.PlanHash) == "" {
		return ConfirmResult{}, errors.New("throw confirmation plan hash is required")
	}
	if strings.TrimSpace(req.PlanHash) != plan.PlanHash {
		return ConfirmResult{}, fmt.Errorf("throw confirmation plan hash %q does not match plan hash %q", strings.TrimSpace(req.PlanHash), plan.PlanHash)
	}
	entityID := strings.TrimSpace(req.EntityID)
	if entityID == "" {
		return ConfirmResult{}, errors.New("confirming entity id is required")
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = "typed_yes"
	}
	confirmation := ConfirmationRecord{
		ID:          plan.ConfirmationID,
		Workspace:   plan.Workspace,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		EntityID:    entityID,
		Method:      method,
		ConfirmedAt: s.now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.confirmations.RecordConfirmation(ctx, confirmation); err != nil {
		return ConfirmResult{}, err
	}
	var pending PendingStatus
	if s.launchKeys != nil {
		pending, err = s.launchKeys.Confirm(ctx, PendingConfirmation{
			PendingID:   plan.ID,
			EntityID:    entityID,
			PlanHash:    plan.PlanHash,
			Flags:       plan.Flags,
			ConfirmedAt: s.now(),
		})
		if err != nil {
			return ConfirmResult{}, err
		}
	}
	return ConfirmResult{
		Plan:         plan,
		Confirmation: confirmation,
		Pending:      pending,
		NextActions:  []string{"start_throw"},
	}, nil
}

func (s Service) RequireStartReady(ctx context.Context, req StartRequest) (StartReadiness, error) {
	if err := ctx.Err(); err != nil {
		return StartReadiness{}, err
	}
	if s.plans == nil {
		return StartReadiness{}, errors.New("throw plan repository is not configured")
	}
	if s.confirmations == nil {
		return StartReadiness{}, errors.New("throw confirmation repository is not configured")
	}
	workspace := workspaceOrDefault(req.Workspace)
	planID := strings.TrimSpace(req.PlanID)
	plan, ok, err := s.plans.GetPlan(ctx, workspace, planID)
	if err != nil {
		return StartReadiness{}, err
	}
	if !ok {
		return StartReadiness{}, fmt.Errorf("throw plan %s does not exist", planID)
	}
	confirmation, ok, err := s.confirmations.GetConfirmation(ctx, workspace, plan.PlanHash)
	if err != nil {
		return StartReadiness{}, err
	}
	if !ok {
		return StartReadiness{}, fmt.Errorf("throw confirmation for plan %s is required", plan.ID)
	}
	var pending PendingStatus
	if s.launchKeys != nil {
		pending, err = s.launchKeys.RequireReady(ctx, plan.ID)
		if err != nil {
			return StartReadiness{
				Ready:        false,
				Plan:         plan,
				Confirmation: confirmation,
				Pending:      pending,
			}, err
		}
	}
	return StartReadiness{
		Ready:        true,
		Plan:         plan,
		Confirmation: confirmation,
		Pending:      pending,
	}, nil
}

func (s Service) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

type planHashInput struct {
	Operation     string                       `json:"operation"`
	Chain         string                       `json:"chain"`
	Targets       []string                     `json:"targets"`
	Modules       []string                     `json:"modules,omitempty"`
	ChainConfig   map[string]string            `json:"chainConfig,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	Flags         operatordomain.ApprovalFlags `json:"flags"`
}

func planHash(input planHashInput) string {
	data, err := json.Marshal(input)
	if err != nil {
		sum := sha256.Sum256([]byte(input.Chain))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableIDComponent(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16]
}

func workspaceOrDefault(workspace string) string {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		return ".hovel"
	}
	return workspace
}

func operationOrDefault(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return DefaultOperation
	}
	return operation
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if cloned := cloneStringMap(config); len(cloned) != 0 {
			out[target] = cloned
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
