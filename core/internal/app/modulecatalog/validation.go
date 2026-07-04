package modulecatalog

import (
	"fmt"
	"sort"
)

type StepRef struct {
	ID       string
	ModuleID string
}

type ConfigView struct {
	Steps         []StepRef
	Targets       []string
	ChainConfig   map[string]string
	TargetConfigs map[string]map[string]string
}

type Issue struct {
	Scope    Scope
	StepID   string
	ModuleID string
	Target   string
	Key      string
	Message  string
}

type Validation struct {
	Valid  bool
	Issues []Issue
}

func (c Catalog) Validate(view ConfigView) Validation {
	var issues []Issue
	if len(view.Steps) == 0 {
		issues = append(issues, Issue{Scope: ScopeChain, Message: "chain has no modules"})
	}
	if len(view.Targets) == 0 {
		issues = append(issues, Issue{Scope: ScopeTarget, Message: "chain has no targets"})
	}

	for _, step := range view.Steps {
		module, ok := c.Find(step.ModuleID)
		if !ok {
			issues = append(issues, Issue{
				Scope:    ScopeChain,
				StepID:   step.ID,
				ModuleID: step.ModuleID,
				Message:  fmt.Sprintf("module %s does not exist", step.ModuleID),
			})
			continue
		}
		if !module.Enabled {
			issues = append(issues, Issue{
				Scope:    ScopeChain,
				StepID:   step.ID,
				ModuleID: step.ModuleID,
				Message:  fmt.Sprintf("module %s is disabled", step.ModuleID),
			})
			continue
		}
		issues = append(issues, validateRequirements(ScopeChain, step, "", module.ChainConfig, view.ChainConfig)...)
		for _, target := range view.Targets {
			issues = append(issues, validateRequirements(ScopeTarget, step, target, module.TargetConfig, view.TargetConfigs[target])...)
		}
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Scope != issues[j].Scope {
			return issues[i].Scope < issues[j].Scope
		}
		if issues[i].Target != issues[j].Target {
			return issues[i].Target < issues[j].Target
		}
		if issues[i].StepID != issues[j].StepID {
			return issues[i].StepID < issues[j].StepID
		}
		return issues[i].Key < issues[j].Key
	})
	return Validation{Valid: len(issues) == 0, Issues: issues}
}

func validateRequirements(scope Scope, step StepRef, target string, requirements []Requirement, values map[string]string) []Issue {
	var issues []Issue
	for _, requirement := range requirements {
		value := values[requirement.Key]
		if value == "" {
			if requirement.Required {
				issues = append(issues, Issue{
					Scope:    scope,
					StepID:   step.ID,
					ModuleID: step.ModuleID,
					Target:   target,
					Key:      requirement.Key,
					Message:  fmt.Sprintf("missing %s config %s", scope, requirement.Key),
				})
			}
			continue
		}
		if err := ValidateValue(requirement, value); err != nil {
			issues = append(issues, Issue{
				Scope:    scope,
				StepID:   step.ID,
				ModuleID: step.ModuleID,
				Target:   target,
				Key:      requirement.Key,
				Message:  fmt.Sprintf("invalid %s config %s: %v", scope, requirement.Key, err),
			})
		}
	}
	return issues
}
