package cli

import (
	"io"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
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
	session          commands.OperatorSession
	modules          modulecatalog.Catalog
	stage            interactiveConfigStage
	chain            string
	items            []configItem
	selected         configItem
	announcedMissing bool
}

func newInteractiveConfigWizard(session commands.OperatorSession, modules modulecatalog.Catalog) *interactiveConfigWizard {
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

func (w *interactiveConfigWizard) ValuePrompt() (string, bool) {
	if w == nil {
		return "", false
	}
	switch w.stage {
	case interactiveConfigSetCurrent, interactiveConfigSetMissing:
		prompt := strings.TrimSpace(w.selected.Prompt())
		return prompt, prompt != ""
	default:
		return "", false
	}
}

func (w *interactiveConfigWizard) Start(stdout, stderr io.Writer) int {
	if w.session == nil {
		writeCLILine(stderr, "active chain is required")
		writeCLILine(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
		return 1
	}
	state := w.session.Snapshot()
	if state.ActiveChain == "" {
		writeCLILine(stderr, "active chain is required")
		writeCLILine(stderr, "\nStart with:\n  chain create <name>\n  chain use <name>")
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
		writeCLIFormat(stdout, "Chain %s configuration canceled\n", chain)
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
		writeCLILine(stdout, "invalid selection")
		w.renderCurrentMenu(stdout)
		return 0
	}

	w.selected = w.items[index-1]
	w.stage = interactiveConfigSetCurrent
	writeCLIFormat(stdout, "Editing %s\n", w.selected.Label())
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
		writeCLIFormat(stdout, "invalid value for %s: %v\n", item.Key, err)
		return 0
	}

	var err error
	if item.Scope == modulecatalog.ScopeTarget {
		err = w.session.SetTargetConfig(item.Target, item.Key, value)
	} else {
		err = w.session.SetChainConfig(item.Key, value)
	}
	if err != nil {
		writeCLILine(stderr, err)
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
	writeCLIFormat(stdout, "Remaining configuration for chain %s\n", w.chain)
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
		writeCLIFormat(stdout, "Remaining configuration for chain %s\n", w.chain)
	}
	return 0
}

func (w *interactiveConfigWizard) complete(stdout io.Writer) int {
	chain := w.session.Snapshot().ActiveChain
	w.reset()
	return completeConfigInteractionForChain(w.session, w.modules, chain, stdout)
}

func (w *interactiveConfigWizard) renderCurrentMenu(stdout io.Writer) {
	state := w.session.Snapshot()
	w.items = availableConfigItems(w.modules, state)
	w.selected = configItem{}
	w.stage = interactiveConfigSelectCurrent

	writeCLIFormat(stdout, "Available configuration for chain %s\n", w.chain)
	if len(w.items) == 0 {
		writeCLILine(stdout, "No configurable values.")
	}
	for i, item := range w.items {
		writeCLIFormat(stdout, "%d) %s\n", i+1, item.Label())
	}
	writeCLILine(stdout, "c) continue")
	writeCLILine(stdout, "select config to edit or c to continue")
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
