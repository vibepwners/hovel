package commandview

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Vibe-Pwners/hovel/internal/adapters/clistyle"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/charmbracelet/glamour"
)

type Renderer struct {
	styles clistyle.Styles
	width  int
}

func New(width int) Renderer {
	if width <= 0 {
		width = clistyle.DefaultWidth
	}
	return Renderer{styles: clistyle.Default(), width: width}
}

func (r Renderer) Render(result commands.Result) (string, bool) {
	switch payload := result.JSON.(type) {
	case commands.ModuleInventoryPayload:
		return r.moduleInventory(payload), true
	case commands.ModuleInspectPayload:
		return r.moduleInspect(payload), true
	case commands.ModuleCheckPayload:
		return r.moduleCheck(payload), true
	case []commands.InstalledPayloadRecord:
		return r.installedPayloads(payload), true
	case []commands.AvailablePayload:
		return r.availablePayloads(payload), true
	case []commands.ThrowPlanRecord:
		return r.throwPlans(payload), true
	case commands.ThrowInspectPayload:
		return r.throwInspect(payload), true
	case commands.ValidationPayload:
		return r.validation(result.Human, payload), true
	default:
		return "", false
	}
}

func (r Renderer) moduleInventory(payload commands.ModuleInventoryPayload) string {
	rows := make([][]string, 0, len(payload.Modules))
	for _, record := range payload.Modules {
		source := record.SourceKind
		if record.Installed {
			source = "installed"
		}
		rows = append(rows, []string{
			record.ID,
			string(record.Type),
			string(record.Scope),
			source,
			record.Summary,
		})
	}
	if len(rows) == 0 {
		return r.styles.Muted.Render("No modules")
	}
	return r.styles.Table([]string{"ID", "TYPE", "SCOPE", "SOURCE", "SUMMARY"}, rows, r.tableWidth())
}

func (r Renderer) moduleInspect(payload commands.ModuleInspectPayload) string {
	meta := r.styles.KeyValue([][2]string{
		{"id", r.styles.Header.Render(payload.ID)},
		{"type", r.styles.Badge(string(payload.Type))},
		{"version", display(payload.Version)},
		{"runtime", display(payload.RuntimeKind)},
		{"author", display(payload.Author)},
		{"enabled", r.styles.Status(fmt.Sprint(payload.Enabled))},
	})

	var sections []string
	if payload.Summary != "" {
		sections = append(sections, r.styles.Header.Render(payload.Summary))
	}
	if payload.Description != "" {
		sections = append(sections, r.renderMarkdown(payload.Description))
	}
	sections = append(sections, meta)
	if len(payload.Tags) > 0 {
		sections = append(sections, r.styles.Cyan.Render("tags")+"  "+strings.Join(payload.Tags, ", "))
	}
	if len(payload.ChainConfig) > 0 {
		sections = append(sections, r.requirements("chain config", payload.ChainConfig))
	}
	if len(payload.TargetConfig) > 0 {
		sections = append(sections, r.requirements("target config", payload.TargetConfig))
	}
	if len(payload.Steps) > 0 {
		sections = append(sections, r.steps(payload.Steps))
	}
	sections = append(sections, r.styles.Muted.Render("Next: chain add "+payload.ID))
	return r.styles.Panel("MODULE", payload.ID, strings.Join(nonEmpty(sections), "\n\n"), r.panelWidth())
}

func (r Renderer) requirements(title string, requirements []modulecatalog.Requirement) string {
	width := r.contentWidth()
	keyWidth := bounded(width/3, 14, 24)
	detailWidth := bounded(width-keyWidth-30, 18, 42)
	rows := make([][]string, 0, len(requirements))
	for _, requirement := range requirements {
		required := "opt"
		if requirement.Required {
			required = "yes"
		}
		detail := requirement.Description
		if len(requirement.Allowed) > 0 {
			detail = joinDetail(detail, "allowed: "+strings.Join(requirement.Allowed, ", "))
		}
		if requirement.Default != "" {
			detail = joinDetail(detail, "default: "+requirement.Default)
		}
		rows = append(rows, []string{
			wrapCell(requirement.Key, keyWidth),
			wrapCell(display(string(requirement.Type)), 10),
			required,
			wrapCell(display(detail), detailWidth),
		})
	}
	return r.styles.Header.Render(strings.ToUpper(title)) + "\n" +
		r.styles.Table([]string{"KEY", "TYPE", "REQ", "DETAIL"}, rows, width)
}

func (r Renderer) steps(steps []commands.ModuleStepPayload) string {
	width := r.contentWidth()
	idWidth := bounded(width/3, 14, 28)
	rows := make([][]string, 0, len(steps))
	for _, step := range steps {
		state := "ready"
		missing := ""
		if !step.Ready {
			state = "blocked"
			if len(step.Missing) > 0 {
				missing = string(step.Missing[0].Type)
				if len(step.Missing) > 1 {
					missing += fmt.Sprintf(" (+%d more)", len(step.Missing)-1)
				}
			}
		}
		rows = append(rows, []string{wrapCell(step.ID, idWidth), wrapCell(step.Kind, 14), state, wrapCell(missing, 20)})
	}
	return r.styles.Header.Render("STEPS") + "\n" +
		r.styles.Table([]string{"ID", "KIND", "STATE", "MISSING"}, rows, width)
}

func (r Renderer) moduleCheck(payload commands.ModuleCheckPayload) string {
	rows := make([][]string, 0, len(payload.Reports))
	for _, report := range payload.Reports {
		label := report.Module
		if label == "" {
			label = report.Subject
		}
		rows = append(rows, []string{string(report.Status), label, fmt.Sprint(report.Failures()), fmt.Sprint(report.Warnings())})
	}
	summary := fmt.Sprintf("%s  failures=%d warnings=%d", r.styles.Status(string(payload.Status)), payload.Failures, payload.Warnings)
	return r.styles.Panel("MODULE CHECKS", summary, r.styles.Table([]string{"STATUS", "MODULE", "FAIL", "WARN"}, rows, r.contentWidth()), r.panelWidth())
}

func (r Renderer) availablePayloads(payloads []commands.AvailablePayload) string {
	if len(payloads) == 0 {
		return r.styles.Muted.Render("No payloads available")
	}
	rows := make([][]string, 0, len(payloads))
	for _, payload := range payloads {
		rows = append(rows, []string{payload.Provider, payload.PayloadID, payload.Platform, payload.Arch, strings.Join(payload.Formats, ", "), payload.Transport})
	}
	return r.styles.Table([]string{"PROVIDER", "PAYLOAD", "PLATFORM", "ARCH", "FORMATS", "TRANSPORT"}, rows, r.tableWidth())
}

func (r Renderer) installedPayloads(records []commands.InstalledPayloadRecord) string {
	if len(records) == 0 {
		return r.styles.Muted.Render("No installed payloads")
	}
	rows := make([][]string, 0, len(records))
	for _, record := range records {
		rows = append(rows, []string{record.Handle, record.State, record.Provider, record.Target, display(record.Transport), display(record.Endpoint)})
	}
	return r.styles.Table([]string{"ID", "STATE", "PROVIDER", "TARGET", "TRANSPORT", "ENDPOINT"}, rows, r.tableWidth())
}

func (r Renderer) throwPlans(plans []commands.ThrowPlanRecord) string {
	if len(plans) == 0 {
		return r.styles.Muted.Render("No throws")
	}
	rows := make([][]string, 0, len(plans))
	for _, plan := range plans {
		rows = append(rows, []string{plan.ID, plan.Chain, fmt.Sprint(len(plan.Targets)), plan.Review, short(plan.PlanHash, 10)})
	}
	return r.styles.Table([]string{"ID", "CHAIN", "TARGETS", "REVIEW", "HASH"}, rows, r.tableWidth())
}

func (r Renderer) throwInspect(payload commands.ThrowInspectPayload) string {
	plan := payload.Plan
	rows := [][2]string{
		{"id", plan.ID},
		{"chain", plan.Chain},
		{"targets", strings.Join(plan.Targets, ", ")},
		{"review", plan.Review},
		{"plan hash", short(plan.PlanHash, 16)},
		{"confirmation", plan.ConfirmationID},
		{"intent", plan.Intent},
	}
	body := r.styles.KeyValue(rows)
	if len(payload.Events) > 0 {
		eventRows := make([][]string, 0, len(payload.Events))
		for _, evt := range payload.Events {
			eventRows = append(eventRows, []string{evt.Timestamp.Format("2006-01-02T15:04:05Z07:00"), string(evt.Level), string(evt.Type), evt.Message})
		}
		body += "\n\n" + r.styles.Header.Render("EVENTS") + "\n" + r.styles.Table([]string{"TIME", "LEVEL", "TYPE", "MESSAGE"}, eventRows, r.contentWidth())
	}
	return r.styles.Panel("THROW", plan.ID, body, r.panelWidth())
}

func (r Renderer) validation(human string, payload commands.ValidationPayload) string {
	title := "CHAIN VALIDATION"
	if payload.Valid {
		return r.styles.Panel(title, r.styles.Status("valid"), strings.TrimSpace(human), r.panelWidth())
	}
	rows := make([][]string, 0, len(payload.Issues))
	for _, issue := range payload.Issues {
		rows = append(rows, []string{string(issue.Scope), issue.ModuleID, issue.Target, issue.Key, issue.Message})
	}
	return r.styles.Panel(title, r.styles.Status("invalid"), r.styles.Table([]string{"SCOPE", "MODULE", "TARGET", "KEY", "MESSAGE"}, rows, r.contentWidth()), r.panelWidth())
}

func (r Renderer) renderMarkdown(value string) string {
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(r.contentWidth()),
	)
	if err != nil {
		return strings.TrimSpace(value)
	}
	rendered, err := renderer.Render(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(rendered)
}

func (r Renderer) tableWidth() int {
	width := r.width
	if width <= 0 {
		width = clistyle.DefaultWidth
	}
	return bounded(width, 64, 120)
}

func (r Renderer) panelWidth() int {
	width := r.width
	if width <= 0 {
		width = clistyle.DefaultWidth
	}
	return bounded(width-2, 64, clistyle.DefaultWidth)
}

func (r Renderer) contentWidth() int {
	return bounded(r.panelWidth()-8, 48, 88)
}

func bounded(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func joinDetail(base, extra string) string {
	base = strings.TrimSpace(base)
	extra = strings.TrimSpace(extra)
	if base == "" {
		return extra
	}
	if extra == "" {
		return base
	}
	return base + "; " + extra
}

func wrapCell(value string, width int) string {
	value = strings.TrimSpace(value)
	if value == "" || width <= 0 {
		return value
	}
	runes := []rune(value)
	var lines []string
	for len(runes) > width {
		cut := width
		for i := width; i > width/2; i-- {
			if unicode.IsSpace(runes[i]) {
				cut = i
				break
			}
		}
		lines = append(lines, strings.TrimSpace(string(runes[:cut])))
		runes = []rune(strings.TrimSpace(string(runes[cut:])))
	}
	if len(runes) > 0 {
		lines = append(lines, string(runes))
	}
	return strings.Join(lines, "\n")
}

func display(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func short(value string, n int) string {
	value = strings.TrimSpace(value)
	if len(value) <= n {
		return value
	}
	return value[:n]
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
