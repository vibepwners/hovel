package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

type huhConfigValue struct {
	Item  configItem
	Value string
}

func (a App) runHuhConfigForm(ctx context.Context, stdout, stderr io.Writer) int {
	if a.session == nil {
		fmt.Fprintln(stderr, "active chain is required")
		fmt.Fprintln(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
		return 1
	}
	state := a.session.Snapshot()
	if state.ActiveChain == "" {
		fmt.Fprintln(stderr, "active chain is required")
		fmt.Fprintln(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
		return 1
	}
	values := newHuhConfigValues(availableConfigItems(a.modules, state))
	if len(values) == 0 {
		fmt.Fprintf(stdout, "No configurable values for chain %s\n", state.ActiveChain)
		return completeConfigInteraction(a.session, a.modules, stdout)
	}
	form := huhConfigForm(state, values, terminalWidth(stdout)).
		WithTheme(hovelHuhTheme()).
		WithInput(os.Stdin).
		WithOutput(stdout)
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Fprintf(stdout, "Chain %s configuration canceled\n", state.ActiveChain)
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := applyHuhConfigValues(a.session, values); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return completeConfigInteraction(a.session, a.modules, stdout)
}

func newHuhConfigValues(items []configItem) []*huhConfigValue {
	values := make([]*huhConfigValue, 0, len(items))
	for _, item := range items {
		value := item.Value
		if strings.TrimSpace(value) == "" {
			value = item.Requirement.Default
		}
		if strings.TrimSpace(value) == "" {
			switch item.Requirement.Type {
			case modulecatalog.ValueBool:
				value = "false"
			case modulecatalog.ValueEnum:
				if len(item.Requirement.Allowed) > 0 {
					value = item.Requirement.Allowed[0]
				}
			}
		}
		values = append(values, &huhConfigValue{Item: item, Value: value})
	}
	return values
}

func huhConfigForm(state operatorsession.State, values []*huhConfigValue, width int) *huh.Form {
	if width <= 0 {
		width = 96
	}
	chainFields := make([]huh.Field, 0)
	targetFields := map[string][]huh.Field{}
	targetOrder := make([]string, 0)
	for _, value := range values {
		field := huhConfigField(value)
		if value.Item.Scope == modulecatalog.ScopeTarget {
			target := value.Item.Target
			if _, ok := targetFields[target]; !ok {
				targetOrder = append(targetOrder, target)
			}
			targetFields[target] = append(targetFields[target], field)
			continue
		}
		chainFields = append(chainFields, field)
	}

	groups := make([]*huh.Group, 0, 1+len(targetOrder))
	if len(chainFields) > 0 {
		groups = append(groups, huh.NewGroup(chainFields...).
			Title("Chain config").
			Description(state.ActiveChain))
	}
	for _, target := range targetOrder {
		groups = append(groups, huh.NewGroup(targetFields[target]...).
			Title("Target config").
			Description(target))
	}
	return huh.NewForm(groups...).WithWidth(width)
}

func huhConfigField(value *huhConfigValue) huh.Field {
	item := value.Item
	title := huhConfigTitle(item)
	description := huhConfigDescription(item.Requirement)
	switch item.Requirement.Type {
	case modulecatalog.ValueBool:
		return huh.NewSelect[string]().
			Key(huhConfigKey(item)).
			Title(title).
			Description(description).
			Options(
				huh.NewOption("false", "false"),
				huh.NewOption("true", "true"),
			).
			Value(&value.Value)
	case modulecatalog.ValueEnum:
		options := make([]huh.Option[string], 0, len(item.Requirement.Allowed))
		for _, allowed := range item.Requirement.Allowed {
			options = append(options, huh.NewOption(allowed, allowed))
		}
		if len(options) > 0 {
			return huh.NewSelect[string]().
				Key(huhConfigKey(item)).
				Title(title).
				Description(description).
				Options(options...).
				Value(&value.Value)
		}
	}
	input := huh.NewInput().
		Key(huhConfigKey(item)).
		Title(title).
		Description(description).
		Placeholder(item.Requirement.Default).
		Value(&value.Value).
		Validate(func(raw string) error {
			if strings.TrimSpace(raw) == "" && !item.Requirement.Required {
				return nil
			}
			return validateConfigValue(item.Requirement, raw)
		})
	if item.Requirement.Secret || item.Requirement.Type == modulecatalog.ValueSecret {
		input.EchoMode(huh.EchoModePassword)
	}
	return input
}

func applyHuhConfigValues(session commands.OperatorSession, values []*huhConfigValue) error {
	for _, value := range values {
		item := value.Item
		raw := strings.TrimSpace(value.Value)
		if raw == "" && !item.Requirement.Required {
			continue
		}
		if err := validateConfigValue(item.Requirement, raw); err != nil {
			return fmt.Errorf("invalid value for %s: %w", item.Key, err)
		}
		if item.Scope == modulecatalog.ScopeTarget {
			if err := session.SetTargetConfig(item.Target, item.Key, raw); err != nil {
				return err
			}
			continue
		}
		if err := session.SetChainConfig(item.Key, raw); err != nil {
			return err
		}
	}
	return nil
}

func completeConfigInteraction(session commands.OperatorSession, modules modulecatalog.Catalog, stdout io.Writer) int {
	state := session.Snapshot()
	return completeConfigInteractionForChain(session, modules, state.ActiveChain, stdout)
}

func completeConfigInteractionForChain(session commands.OperatorSession, modules modulecatalog.Catalog, chain string, stdout io.Writer) int {
	state := session.Snapshot()
	validation := commands.ValidateState(modules, state)
	if !validation.Valid {
		fmt.Fprintf(stdout, "Chain %s still needs attention\n", chain)
		for _, issue := range validation.Issues {
			fmt.Fprintln(stdout, "[!] "+issue.Message)
		}
		return 1
	}
	fmt.Fprintf(stdout, "Chain %s configuration complete\n", chain)
	return 0
}

func huhConfigTitle(item configItem) string {
	if item.Scope == modulecatalog.ScopeTarget {
		return item.Target + " " + item.Key
	}
	return item.Key
}

func huhConfigDescription(requirement modulecatalog.Requirement) string {
	var parts []string
	typeName := string(requirement.Type)
	if typeName == "" {
		typeName = "string"
	}
	if requirement.Required {
		parts = append(parts, "required")
	} else {
		parts = append(parts, "optional")
	}
	parts = append(parts, typeName)
	if requirement.Default != "" {
		parts = append(parts, "default "+modulecatalog.DisplayValue(requirement, requirement.Default))
	}
	if requirement.Description != "" {
		parts = append(parts, requirement.Description)
	}
	return strings.Join(parts, " - ")
}

func huhConfigKey(item configItem) string {
	if item.Scope == modulecatalog.ScopeTarget {
		return "target:" + item.Target + ":" + item.Key
	}
	return "chain:" + item.Key
}

func hovelHuhTheme() *huh.Theme {
	theme := huh.ThemeCharm()
	theme.Focused.Title = theme.Focused.Title.Foreground(lipgloss.Color("#00e5ff")).Bold(true)
	theme.Focused.Description = theme.Focused.Description.Foreground(lipgloss.Color("#9ca3af"))
	theme.Focused.SelectSelector = theme.Focused.SelectSelector.Foreground(lipgloss.Color("#ff2bd6"))
	theme.Focused.TextInput.Prompt = theme.Focused.TextInput.Prompt.Foreground(lipgloss.Color("#ff2bd6"))
	theme.Focused.TextInput.Cursor = theme.Focused.TextInput.Cursor.Foreground(lipgloss.Color("#22c55e"))
	theme.Focused.ErrorMessage = theme.Focused.ErrorMessage.Foreground(lipgloss.Color("#ff0033"))
	theme.Group.Title = theme.Group.Title.Foreground(lipgloss.Color("#ff2bd6")).Bold(true)
	theme.Group.Description = theme.Group.Description.Foreground(lipgloss.Color("#9ca3af"))
	return theme
}

func shouldUseHuhConfig(stdout io.Writer) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HOVEL_CONFIG_INTERACTIVE"))) {
	case "huh", "form":
		return true
	case "wizard", "prompt", "line":
		return false
	}
	if terminalWidth(stdout) <= 0 {
		return false
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
