package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	prompt "github.com/c-bata/go-prompt"
)

type interactiveConfigStage int

const (
	interactiveConfigIdle interactiveConfigStage = iota
	interactiveConfigSelectCurrent
	interactiveConfigSetCurrent
	interactiveConfigSetMissing
)

type interactiveConfigWizard struct {
	session          *operatorsession.Session
	modules          modulecatalog.Catalog
	stage            interactiveConfigStage
	chain            string
	items            []configItem
	selected         configItem
	announcedMissing bool
}

func newInteractiveConfigWizard(session *operatorsession.Session, modules modulecatalog.Catalog) *interactiveConfigWizard {
	return &interactiveConfigWizard{
		session: session,
		modules: modules,
	}
}

func (w *interactiveConfigWizard) Active() bool {
	return w != nil && w.stage != interactiveConfigIdle
}

func (w *interactiveConfigWizard) PromptMode() string {
	if w == nil {
		return "config"
	}
	switch w.stage {
	case interactiveConfigSelectCurrent:
		return "config select"
	case interactiveConfigSetCurrent, interactiveConfigSetMissing:
		return "config value"
	default:
		return "config"
	}
}

func (w *interactiveConfigWizard) Start(stdout, stderr io.Writer) int {
	if w.session == nil {
		fmt.Fprintln(stderr, "active chain is required")
		fmt.Fprintln(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
		return 1
	}
	state := w.session.Snapshot()
	if state.ActiveChain == "" {
		fmt.Fprintln(stderr, "active chain is required")
		fmt.Fprintln(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
		return 1
	}

	w.chain = state.ActiveChain
	w.announcedMissing = false
	w.renderCurrentMenu(stdout)
	return 0
}

func (w *interactiveConfigWizard) HandleLine(line string, stdout, stderr io.Writer) int {
	answer := strings.TrimSpace(line)
	if strings.EqualFold(answer, "cancel") {
		chain := w.chain
		w.reset()
		fmt.Fprintf(stdout, "Chain %s configuration canceled\n", chain)
		return 0
	}

	switch w.stage {
	case interactiveConfigSelectCurrent:
		return w.selectCurrent(answer, stdout, stderr)
	case interactiveConfigSetCurrent:
		return w.acceptValue(answer, stdout, stderr, true)
	case interactiveConfigSetMissing:
		return w.acceptValue(answer, stdout, stderr, false)
	default:
		return 0
	}
}

func (w *interactiveConfigWizard) Suggestions(line string) []prompt.Suggest {
	prefix := strings.TrimSpace(line)
	switch w.stage {
	case interactiveConfigSelectCurrent:
		suggestions := []prompt.Suggest{
			{Text: "c", Description: "Continue to missing required config."},
			{Text: "continue", Description: "Continue to missing required config."},
			{Text: "cancel", Description: "Cancel interactive configuration."},
		}
		for i, item := range w.items {
			suggestions = append(suggestions, prompt.Suggest{
				Text:        strconv.Itoa(i + 1),
				Description: item.Label(),
			})
		}
		return filterSuggestions(suggestions, prefix)
	case interactiveConfigSetCurrent, interactiveConfigSetMissing:
		return configValueSuggestions(w.selected, prefix)
	default:
		return nil
	}
}

func (w *interactiveConfigWizard) selectCurrent(answer string, stdout, stderr io.Writer) int {
	switch strings.ToLower(answer) {
	case "c", "continue":
		return w.beginMissing(stdout, stderr)
	case "":
		w.renderCurrentMenu(stdout)
		return 0
	}

	index, err := strconv.Atoi(answer)
	if err != nil || index < 1 || index > len(w.items) {
		fmt.Fprintln(stdout, "invalid selection")
		w.renderCurrentMenu(stdout)
		return 0
	}

	w.selected = w.items[index-1]
	w.stage = interactiveConfigSetCurrent
	fmt.Fprintf(stdout, "Editing %s\n", w.selected.Label())
	w.renderValuePrompt(stdout)
	return 0
}

func (w *interactiveConfigWizard) acceptValue(answer string, stdout, stderr io.Writer, returnToMenu bool) int {
	item := w.selected
	value := strings.TrimSpace(answer)
	if value == "" && item.Value != "" {
		if returnToMenu {
			w.renderCurrentMenu(stdout)
			return 0
		}
		return w.promptNextMissing(stdout, stderr)
	}

	if err := validateConfigValue(item.Requirement, value); err != nil {
		fmt.Fprintf(stdout, "invalid value for %s: %v\n", item.Key, err)
		w.renderValuePrompt(stdout)
		return 0
	}

	var err error
	if item.Scope == modulecatalog.ScopeTarget {
		err = w.session.SetTargetConfig(item.Target, item.Key, value)
	} else {
		err = w.session.SetChainConfig(item.Key, value)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		w.reset()
		return 1
	}

	if returnToMenu {
		w.renderCurrentMenu(stdout)
		return 0
	}
	return w.promptNextMissing(stdout, stderr)
}

func (w *interactiveConfigWizard) beginMissing(stdout, stderr io.Writer) int {
	w.announcedMissing = true
	fmt.Fprintf(stdout, "Remaining configuration for chain %s\n", w.chain)
	return w.promptNextMissing(stdout, stderr)
}

func (w *interactiveConfigWizard) promptNextMissing(stdout, stderr io.Writer) int {
	state := w.session.Snapshot()
	items := missingConfigItems(w.modules, state)
	if len(items) == 0 {
		return w.complete(stdout)
	}

	w.items = items
	w.selected = items[0]
	w.stage = interactiveConfigSetMissing
	if !w.announcedMissing {
		w.announcedMissing = true
		fmt.Fprintf(stdout, "Remaining configuration for chain %s\n", w.chain)
	}
	w.renderValuePrompt(stdout)
	return 0
}

func (w *interactiveConfigWizard) complete(stdout io.Writer) int {
	state := w.session.Snapshot()
	validation := w.modules.Validate(configView(state))
	w.reset()
	if !validation.Valid {
		fmt.Fprintf(stdout, "Chain %s still needs attention\n", state.ActiveChain)
		for _, issue := range validation.Issues {
			fmt.Fprintln(stdout, "[!] "+issue.Message)
		}
		return 1
	}
	fmt.Fprintf(stdout, "Chain %s configuration complete\n", state.ActiveChain)
	return 0
}

func (w *interactiveConfigWizard) renderCurrentMenu(stdout io.Writer) {
	state := w.session.Snapshot()
	w.items = currentConfigItems(w.modules, state)
	w.selected = configItem{}
	w.stage = interactiveConfigSelectCurrent

	fmt.Fprintf(stdout, "Current configuration for chain %s\n", w.chain)
	if len(w.items) == 0 {
		fmt.Fprintln(stdout, "No current config values.")
	}
	for i, item := range w.items {
		fmt.Fprintf(stdout, "%d) %s\n", i+1, item.Label())
	}
	fmt.Fprintln(stdout, "c) continue")
	fmt.Fprintln(stdout, "select config to edit or c to continue")
}

func (w *interactiveConfigWizard) renderValuePrompt(stdout io.Writer) {
	fmt.Fprintln(stdout, w.selected.Prompt())
}

func (w *interactiveConfigWizard) reset() {
	w.stage = interactiveConfigIdle
	w.chain = ""
	w.items = nil
	w.selected = configItem{}
	w.announcedMissing = false
}

func configValueSuggestions(item configItem, prefix string) []prompt.Suggest {
	suggestions := []prompt.Suggest{
		{Text: "cancel", Description: "Cancel interactive configuration."},
	}

	requirement := item.Requirement
	switch requirement.Type {
	case modulecatalog.ValueBool:
		suggestions = append(suggestions,
			prompt.Suggest{Text: "true", Description: "Boolean true."},
			prompt.Suggest{Text: "false", Description: "Boolean false."},
		)
	case modulecatalog.ValueEnum:
		for _, allowed := range requirement.Allowed {
			suggestions = append(suggestions, prompt.Suggest{Text: allowed, Description: requirement.Description})
		}
	}

	if requirement.Default != "" {
		suggestions = append(suggestions, prompt.Suggest{Text: requirement.Default, Description: "Default value."})
	}
	if item.Value != "" && !requirement.Secret && requirement.Type != modulecatalog.ValueSecret {
		suggestions = append(suggestions, prompt.Suggest{Text: item.Value, Description: "Current value."})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func filterSuggestions(suggestions []prompt.Suggest, prefix string) []prompt.Suggest {
	if prefix == "" {
		return suggestions
	}
	var filtered []prompt.Suggest
	for _, suggestion := range suggestions {
		if strings.HasPrefix(suggestion.Text, prefix) {
			filtered = append(filtered, suggestion)
		}
	}
	return filtered
}

func dedupeSuggestions(suggestions []prompt.Suggest) []prompt.Suggest {
	seen := map[string]bool{}
	var out []prompt.Suggest
	for _, suggestion := range suggestions {
		if seen[suggestion.Text] {
			continue
		}
		seen[suggestion.Text] = true
		out = append(out, suggestion)
	}
	return out
}
