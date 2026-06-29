package commands

import (
	"context"
	"fmt"
	"strings"
)

type ModuleCheckStatus string

const (
	ModuleCheckPass ModuleCheckStatus = "pass"
	ModuleCheckWarn ModuleCheckStatus = "warn"
	ModuleCheckFail ModuleCheckStatus = "fail"
)

type ModuleCheckRequest struct {
	Reference string
	Workspace string
	Config    string
}

type ModuleCheckReport struct {
	Subject string            `json:"subject"`
	Module  string            `json:"module,omitempty"`
	Status  ModuleCheckStatus `json:"status"`
	Checks  []ModuleCheckItem `json:"checks"`
}

type ModuleCheckItem struct {
	Name    string            `json:"name"`
	Status  ModuleCheckStatus `json:"status"`
	Message string            `json:"message"`
}

type ModuleCheckPayload struct {
	Status   ModuleCheckStatus   `json:"status"`
	Reports  []ModuleCheckReport `json:"reports"`
	Failures int                 `json:"failures"`
	Warnings int                 `json:"warnings"`
}

type ModuleChecker interface {
	CheckModule(context.Context, ModuleCheckRequest) (ModuleCheckReport, error)
}

func modulesCheckHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.ModuleChecks == nil {
			return Result{}, fmt.Errorf("module checks are not configured")
		}
		references, err := moduleCheckReferences(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		payload := ModuleCheckPayload{Status: ModuleCheckPass}
		for _, reference := range references {
			report, err := runtime.ModuleChecks.CheckModule(ctx, ModuleCheckRequest{
				Reference: reference,
				Workspace: workspaceFromInvocation(invocation),
				Config:    invocation.Option("config"),
			})
			if err != nil {
				return Result{}, err
			}
			report.Normalize()
			payload.Reports = append(payload.Reports, report)
			payload.Failures += report.Failures()
			payload.Warnings += report.Warnings()
		}
		if payload.Failures > 0 {
			payload.Status = ModuleCheckFail
		} else if payload.Warnings > 0 {
			payload.Status = ModuleCheckWarn
		}
		exitCode := 0
		if payload.Failures > 0 || invocation.Flag("warnings-as-errors") && payload.Warnings > 0 {
			exitCode = 1
		}
		return Result{
			Human:    moduleCheckHuman(payload, invocation.Flag("all")),
			JSON:     payload,
			ExitCode: exitCode,
		}, nil
	}
}

func moduleCheckReferences(ctx context.Context, runtime Runtime, invocation Invocation) ([]string, error) {
	reference := strings.TrimSpace(invocation.Positional("module"))
	if invocation.Flag("all") {
		if reference != "" {
			return nil, fmt.Errorf("--all cannot be combined with a module reference")
		}
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return nil, err
		}
		modules := db.List()
		if len(modules) == 0 {
			return nil, fmt.Errorf("no modules available to check")
		}
		references := make([]string, 0, len(modules))
		for _, module := range modules {
			references = append(references, module.ID)
		}
		return references, nil
	}
	if reference == "" {
		return nil, fmt.Errorf("module reference is required unless --all is set")
	}
	return []string{reference}, nil
}

func (r *ModuleCheckReport) Normalize() {
	r.Subject = strings.TrimSpace(r.Subject)
	r.Module = strings.TrimSpace(r.Module)
	if r.Subject == "" {
		r.Subject = r.Module
	}
	if r.Status == "" {
		r.Status = ModuleCheckPass
	}
	for i := range r.Checks {
		r.Checks[i].Name = strings.TrimSpace(r.Checks[i].Name)
		r.Checks[i].Message = strings.TrimSpace(r.Checks[i].Message)
		if r.Checks[i].Status == "" {
			r.Checks[i].Status = ModuleCheckPass
		}
		switch r.Checks[i].Status {
		case ModuleCheckFail:
			r.Status = ModuleCheckFail
		case ModuleCheckWarn:
			if r.Status != ModuleCheckFail {
				r.Status = ModuleCheckWarn
			}
		}
	}
}

func (r ModuleCheckReport) Failures() int {
	count := 0
	for _, check := range r.Checks {
		if check.Status == ModuleCheckFail {
			count++
		}
	}
	return count
}

func (r ModuleCheckReport) Warnings() int {
	count := 0
	for _, check := range r.Checks {
		if check.Status == ModuleCheckWarn {
			count++
		}
	}
	return count
}

func moduleCheckHuman(payload ModuleCheckPayload, all bool) string {
	if len(payload.Reports) == 1 && !all {
		return singleModuleCheckHuman(payload.Reports[0])
	}
	passed := 0
	for _, report := range payload.Reports {
		if report.Status != ModuleCheckFail {
			passed++
		}
	}
	lines := []string{
		"MODULE CHECKS",
		fmt.Sprintf("summary %d passed, %d failed, %d warnings", passed, len(payload.Reports)-passed, payload.Warnings),
		"",
		"STATUS  MODULE",
		"------  ------",
	}
	for _, report := range payload.Reports {
		label := report.Module
		if label == "" {
			label = report.Subject
		}
		lines = append(lines, fmt.Sprintf("%-7s %s", displayCheckStatus(report.Status), label))
	}
	return strings.Join(lines, "\n")
}

func singleModuleCheckHuman(report ModuleCheckReport) string {
	lines := []string{
		"MODULE CHECK " + report.Subject,
		fmt.Sprintf("status  %s", displayCheckStatus(report.Status)),
	}
	if report.Module != "" && report.Module != report.Subject {
		lines = append(lines, "module  "+report.Module)
	}
	lines = append(lines, "", "CHECK   NAME                         MESSAGE", "-----   ----                         -------")
	for _, check := range report.Checks {
		lines = append(lines, fmt.Sprintf("%s %-28s %s", displayCheckStatus(check.Status), check.Name, check.Message))
	}
	return strings.Join(lines, "\n")
}

func displayCheckStatus(status ModuleCheckStatus) string {
	switch status {
	case ModuleCheckFail:
		return "❌ FAIL"
	case ModuleCheckWarn:
		return "⚠ WARN"
	default:
		return "✅ PASS"
	}
}
