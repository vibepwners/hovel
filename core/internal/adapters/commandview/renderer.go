package commandview

import (
	"fmt"
	"sort"
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
	case commands.ArtifactRecord:
		return r.artifactInspect(payload), true
	case []commands.ArtifactRecord:
		return r.artifacts(payload), true
	case []commands.InstalledPayloadRecord:
		return r.installedPayloads(payload), true
	case []commands.AvailablePayload:
		return r.availablePayloads(payload), true
	case []commands.SessionRef:
		return r.sessions(payload), true
	case commands.SessionRef:
		return r.session(payload), true
	case []commands.PayloadCommand:
		return r.payloadCommands(payload), true
	case commands.PayloadCommandResult:
		return r.payloadCommandResult(result.Human, payload), true
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
	if payload.Mesh != nil {
		details := []string{
			fmt.Sprintf("%d nodes", meshNodeCount(payload)),
			fmt.Sprintf("%d tasks", len(payload.Mesh.Tasks)),
			fmt.Sprintf("%d triggers", len(payload.Mesh.Triggers)),
		}
		if len(payload.Mesh.Capabilities) > 0 {
			details = append(details, "capabilities: "+strings.Join(payload.Mesh.Capabilities, ", "))
		}
		sections = append(sections, r.styles.Cyan.Render("mesh")+"  "+strings.Join(details, "; "))
	}
	sections = append(sections, r.styles.Muted.Render("Next: chain add "+payload.ID))
	return r.styles.Panel("MODULE", payload.ID, strings.Join(nonEmpty(sections), "\n\n"), r.panelWidth())
}

func meshNodeCount(payload commands.ModuleInspectPayload) int {
	if payload.Mesh == nil || payload.Mesh.Topology == nil {
		return 0
	}
	return len(payload.Mesh.Topology.Nodes)
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

func (r Renderer) artifacts(records []commands.ArtifactRecord) string {
	if len(records) == 0 {
		return r.styles.Muted.Render("No artifacts")
	}
	rows := make([][]string, 0, len(records))
	for _, record := range records {
		rows = append(rows, []string{
			short(record.ID, 18),
			short(record.ThrowID, 18),
			wrapCell(record.Name, 24),
			display(record.Kind),
			formatBytes(record.Size),
			wrapCell(record.Path, 36),
		})
	}
	return r.styles.Table([]string{"ID", "THROW", "NAME", "KIND", "SIZE", "PATH"}, rows, r.tableWidth())
}

func (r Renderer) artifactInspect(record commands.ArtifactRecord) string {
	valueWidth := bounded(r.contentWidth()-12, 24, 72)
	body := r.styles.KeyValue([][2]string{
		{"id", r.styles.Header.Render(record.ID)},
		{"name", display(record.Name)},
		{"kind", display(record.Kind)},
		{"throw", display(record.ThrowID)},
		{"run", display(record.RunID)},
		{"module", display(record.ModuleID)},
		{"target", display(record.Target)},
		{"size", formatBytes(record.Size)},
		{"sha256", wrapCell(display(record.SHA256), valueWidth)},
		{"path", wrapCell(display(record.Path), valueWidth)},
		{"created", display(record.CreatedAt)},
	})
	return r.styles.Panel("ARTIFACT", record.ID, body, r.panelWidth())
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

func (r Renderer) sessions(sessions []commands.SessionRef) string {
	if len(sessions) == 0 {
		return r.styles.Muted.Render("No sessions")
	}
	rows := make([][]string, 0, len(sessions))
	for _, session := range sessions {
		rows = append(rows, []string{
			wrapCell(session.ID, 28),
			display(session.Kind),
			r.styles.Status(display(session.State)),
			wrapCell(display(session.Target), 20),
			wrapCell(display(session.Name), 48),
		})
	}
	return r.styles.Table([]string{"ID", "KIND", "STATE", "TARGET", "NAME"}, rows, 0)
}

func (r Renderer) session(session commands.SessionRef) string {
	rows := [][2]string{
		{"id", r.styles.Header.Render(session.ID)},
		{"kind", display(session.Kind)},
		{"state", r.styles.Status(display(session.State))},
		{"target", display(session.Target)},
		{"name", display(session.Name)},
		{"transport", display(session.Transport)},
	}
	if session.RunID != "" {
		rows = append(rows, [2]string{"run", session.RunID})
	}
	if session.ModuleID != "" {
		rows = append(rows, [2]string{"module", session.ModuleID})
	}
	if session.InstalledPayloadID != "" {
		rows = append(rows, [2]string{"payload", session.InstalledPayloadID})
	}
	if len(session.Capabilities) > 0 {
		rows = append(rows, [2]string{"capabilities", strings.Join(session.Capabilities, ", ")})
	}
	return r.styles.Panel("SESSION", session.ID, r.styles.KeyValue(rows), r.panelWidth())
}

func (r Renderer) payloadCommands(commandsList []commands.PayloadCommand) string {
	if len(commandsList) == 0 {
		return r.styles.Muted.Render("No payload commands")
	}
	width := r.tableWidth()
	rows := make([][]string, 0, len(commandsList))
	for _, command := range commandsList {
		rows = append(rows, []string{
			wrapCell(command.Name, 22),
			r.styles.Status(commands.PayloadCommandEffect(command)),
			wrapCell(display(command.Summary), bounded(width/2, 24, 52)),
		})
	}
	return r.styles.Table([]string{"COMMAND", "EFFECT", "SUMMARY"}, rows, width)
}

func (r Renderer) payloadCommandResult(human string, result commands.PayloadCommandResult) string {
	title := commandResultTitle(human)
	sections := []string{}
	if result.Summary != "" {
		sections = append(sections, r.styles.Header.Render(result.Summary))
	}
	if len(result.Fields) > 0 {
		sections = append(sections, r.commandFields(result.Fields))
	}
	if result.Stdout != "" {
		sections = append(sections, r.commandOutput("STDOUT", result.Stdout))
	}
	if result.Stderr != "" {
		sections = append(sections, r.commandOutput("STDERR", result.Stderr))
	}
	if len(result.Artifacts) > 0 {
		sections = append(sections, r.commandArtifacts(result.Artifacts))
	}
	body := strings.Join(nonEmpty(sections), "\n\n")
	if body == "" {
		body = r.styles.Muted.Render("No output")
	}
	return r.styles.Panel(title, result.Command, body, r.panelWidth())
}

func commandResultTitle(human string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(human), "\n")
	line = strings.ToLower(line)
	switch {
	case strings.HasPrefix(line, "session command"):
		return "SESSION COMMAND"
	case strings.HasPrefix(line, "payload command"):
		return "PAYLOAD COMMAND"
	default:
		return "COMMAND"
	}
}

func (r Renderer) commandFields(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([][2]string, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, [2]string{key, fields[key]})
	}
	return r.styles.Header.Render("FIELDS") + "\n" + r.styles.KeyValue(rows)
}

func (r Renderer) commandOutput(title, value string) string {
	return r.styles.Header.Render(title) + "\n" + commands.PrettyCommandOutput(value)
}

func (r Renderer) commandArtifacts(artifacts []commands.PayloadCommandArtifact) string {
	rows := make([][]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		rows = append(rows, []string{
			wrapCell(display(artifact.Name), 24),
			display(artifact.Kind),
			wrapCell(display(artifact.Path), 36),
		})
	}
	return r.styles.Header.Render("ARTIFACTS") + "\n" +
		r.styles.Table([]string{"NAME", "KIND", "PATH"}, rows, r.contentWidth())
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

func formatBytes(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(size)/(1024*1024))
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
