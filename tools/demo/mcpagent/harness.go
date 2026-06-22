package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultFrameDelay = 160 * time.Millisecond
	defaultTokenDelay = 14 * time.Millisecond
)

type Options struct {
	HovelPath    string
	Workspace    string
	Operation    string
	Chain        string
	EntityID     string
	DisplayName  string
	MCPReadPath  string
	MCPWritePath string
	Prompt       string
	Scenario     string
	Payload      string
	Delay        time.Duration
	TokenDelay   time.Duration
	Color        bool
	Out          io.Writer
	Err          io.Writer
}

type mcpSession interface {
	ListTools(context.Context, *mcpsdk.ListToolsParams) (*mcpsdk.ListToolsResult, error)
	CallTool(context.Context, *mcpsdk.CallToolParams) (*mcpsdk.CallToolResult, error)
	Close() error
}

type connectFunc func(context.Context, Options) (mcpSession, string, error)

func run(ctx context.Context, opts Options) error {
	connect := connectCommandSession
	if opts.MCPReadPath != "" || opts.MCPWritePath != "" {
		connect = connectPipeSession
	}
	return runWithConnect(ctx, opts, connect)
}

func runWithConnect(ctx context.Context, opts Options, connect connectFunc) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Err == nil {
		opts.Err = io.Discard
	}
	if opts.HovelPath == "" {
		opts.HovelPath = "hovel"
	}
	if opts.Workspace == "" {
		opts.Workspace = ".hovel"
	}
	if opts.Operation == "" {
		opts.Operation = "demo"
	}
	if opts.Chain == "" {
		opts.Chain = "mock-survey-exploit-demo"
	}
	if opts.Scenario == "" {
		opts.Scenario = "throw"
	}
	if opts.Prompt == "" {
		if opts.Scenario == "squatter" {
			opts.Prompt = "Operate the registered Squatter implant through Hovel MCP"
		} else {
			opts.Prompt = "Throw the configured mock exploit through Hovel MCP"
		}
	}
	if opts.Scenario == "squatter" {
		return runSquatterWithConnect(ctx, opts, connect)
	}

	renderer := newTranscriptRenderer(opts.Out, opts.Color, opts.Delay, opts.TokenDelay, opts.Prompt)
	renderer.header("Mock Codex Agent", []string{
		"model: mock-codex",
		"transport: " + transportLabel(opts),
		"workspace: " + opts.Workspace,
		"operation: " + opts.Operation,
		"chain: " + opts.Chain,
	})
	renderer.user(opts.Prompt)
	renderer.assistant("I will inspect Hovel state first, verify the selected chain, then call hovel_throw_start with an explicit auditable confirmation bypass.")

	session, stderr, err := connect(ctx, opts)
	if err != nil {
		if stderr != "" {
			fmt.Fprintf(opts.Err, "%s\n", stderr)
		}
		return err
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}
	names := toolNames(tools)
	if err := requireTools(names, []string{
		"hovel_operator_identity",
		"hovel_operator_list_entities",
		"hovel_operation_list",
		"hovel_workspace_snapshot",
		"hovel_throw_start",
	}); err != nil {
		return err
	}
	renderer.tool("tools/list", strings.Join(names, "\n"))

	identity, err := callAndDecode[operatorIdentityOutput](ctx, session, "hovel_operator_identity", nil)
	if err != nil {
		return err
	}
	renderer.tool("hovel_operator_identity", fmt.Sprintf(
		"entity: %s\nkind: %s\nagent: %t\noperation: %s\nactive_chain: %s",
		identity.Entity.ID,
		identity.Entity.Kind,
		identity.Entity.Agent,
		identity.Entity.Operation,
		identity.Entity.ActiveChain,
	))

	entities, err := callAndDecode[operatorListEntitiesOutput](ctx, session, "hovel_operator_list_entities", map[string]any{
		"operation": opts.Operation,
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_operator_list_entities", summarizeEntities(entities))

	operations, err := callAndDecode[operationListOutput](ctx, session, "hovel_operation_list", map[string]any{
		"operation": opts.Operation,
		"chain":     opts.Chain,
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_operation_list", summarizeOperations(operations.Operations))

	snapshot, err := callAndDecode[workspaceSnapshotOutput](ctx, session, "hovel_workspace_snapshot", map[string]any{
		"operation": opts.Operation,
		"chain":     opts.Chain,
	})
	if err != nil {
		return err
	}
	summary := summarizeSnapshot(snapshot, opts.Operation, opts.Chain)
	renderer.tool("hovel_workspace_snapshot", summary)

	throwOut, err := callAndDecode[throwStartOutput](ctx, session, "hovel_throw_start", map[string]any{
		"operation": opts.Operation,
		"chain":     opts.Chain,
		"nowBypass": true,
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_throw_start", summarizeThrow(throwOut))
	renderer.assistant("Hovel throw completed. The mock exploit opened an interactive shell session and the result came back through structured MCP output.")
	return nil
}

func runSquatterWithConnect(ctx context.Context, opts Options, connect connectFunc) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Err == nil {
		opts.Err = io.Discard
	}
	if opts.HovelPath == "" {
		opts.HovelPath = "hovel"
	}
	if opts.Workspace == "" {
		opts.Workspace = ".hovel"
	}
	if opts.Operation == "" {
		opts.Operation = "demo"
	}
	if opts.Payload == "" {
		opts.Payload = "p1"
	}
	if opts.Prompt == "" {
		opts.Prompt = "Operate the registered Squatter implant through Hovel MCP"
	}

	renderer := newTranscriptRenderer(opts.Out, opts.Color, opts.Delay, opts.TokenDelay, opts.Prompt)
	renderer.header("Mock Codex Agent", []string{
		"model: mock-codex",
		"transport: " + transportLabel(opts),
		"workspace: " + opts.Workspace,
		"operation: " + opts.Operation,
		"payload: " + opts.Payload,
	})
	renderer.user(opts.Prompt)
	renderer.assistant("I will use Hovel's payload-command tools so Squatter stays provider-owned and no raw session is exposed.")

	session, stderr, err := connect(ctx, opts)
	if err != nil {
		if stderr != "" {
			fmt.Fprintf(opts.Err, "%s\n", stderr)
		}
		return err
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}
	names := toolNames(tools)
	if err := requireTools(names, []string{
		"hovel_operator_identity",
		"hovel_workspace_snapshot",
		"hovel_payload_command_list",
		"hovel_payload_command_call",
	}); err != nil {
		return err
	}
	renderer.tool("tools/list", strings.Join(names, "\n"))

	identity, err := callAndDecode[operatorIdentityOutput](ctx, session, "hovel_operator_identity", nil)
	if err != nil {
		return err
	}
	renderer.tool("hovel_operator_identity", fmt.Sprintf(
		"entity: %s\nkind: %s\nagent: %t\noperation: %s",
		identity.Entity.ID,
		identity.Entity.Kind,
		identity.Entity.Agent,
		identity.Entity.Operation,
	))

	commands, err := callAndDecode[payloadCommandListOutput](ctx, session, "hovel_payload_command_list", map[string]any{
		"payload": opts.Payload,
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_payload_command_list", summarizePayloadCommands(commands))

	cmdOut, err := callAndDecode[payloadCommandCallOutput](ctx, session, "hovel_payload_command_call", map[string]any{
		"payload": opts.Payload,
		"command": "cmd",
		"args":    []string{"echo squatter-mcp-cmd-ok"},
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_payload_command_call cmd", summarizePayloadCommandResult(cmdOut.Result))

	putOut, err := callAndDecode[payloadCommandCallOutput](ctx, session, "hovel_payload_command_call", map[string]any{
		"payload":       opts.Payload,
		"command":       "putfile",
		"args":          []string{"agent-upload.txt"},
		"inputData":     "squatter mcp upload ok\n",
		"inputEncoding": "utf-8",
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_payload_command_call putfile", summarizePayloadCommandResult(putOut.Result))

	getOut, err := callAndDecode[payloadCommandCallOutput](ctx, session, "hovel_payload_command_call", map[string]any{
		"payload": opts.Payload,
		"command": "getfile",
		"args":    []string{"agent-upload.txt"},
	})
	if err != nil {
		return err
	}
	renderer.tool("hovel_payload_command_call getfile", summarizePayloadCommandResult(getOut.Result))
	renderer.assistant("Squatter responded through provider commands: cmd executed, putfile uploaded content, and getfile returned a Hovel artifact.")
	return nil
}

func connectCommandSession(ctx context.Context, opts Options) (mcpSession, string, error) {
	var stderr bytes.Buffer
	args := []string{
		"mcp",
		"--workspace", opts.Workspace,
		"--op", opts.Operation,
		"--chain", opts.Chain,
		"--entity-id", opts.EntityID,
		"--display-name", opts.DisplayName,
	}
	cmd := exec.CommandContext(ctx, opts.HovelPath, args...)
	cmd.Stderr = &stderr

	client := mcpsdk.NewClient(&mcpsdk.Implementation{
		Name:    "hovel-mock-agent",
		Title:   "Hovel Mock Agent",
		Version: "0.1.0",
	}, nil)
	session, err := client.Connect(ctx, &mcpsdk.CommandTransport{
		Command:           cmd,
		TerminateDuration: time.Second,
	}, nil)
	if err != nil {
		return nil, strings.TrimSpace(stderr.String()), fmt.Errorf("connect to hovel mcp: %w", err)
	}
	return session, "", nil
}

func connectPipeSession(ctx context.Context, opts Options) (mcpSession, string, error) {
	if opts.MCPReadPath == "" || opts.MCPWritePath == "" {
		return nil, "", fmt.Errorf("--mcp-read and --mcp-write must be provided together")
	}
	reader, err := os.OpenFile(opts.MCPReadPath, os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open MCP read pipe: %w", err)
	}
	writer, err := os.OpenFile(opts.MCPWritePath, os.O_RDWR, 0)
	if err != nil {
		_ = reader.Close()
		return nil, "", fmt.Errorf("open MCP write pipe: %w", err)
	}

	client := mcpsdk.NewClient(&mcpsdk.Implementation{
		Name:    "hovel-mock-agent",
		Title:   "Hovel Mock Agent",
		Version: "0.1.0",
	}, nil)
	session, err := client.Connect(ctx, &mcpsdk.IOTransport{
		Reader: reader,
		Writer: writer,
	}, nil)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, "", fmt.Errorf("connect to hovel mcp pipes: %w", err)
	}
	return session, "", nil
}

func transportLabel(opts Options) string {
	if opts.MCPReadPath != "" || opts.MCPWritePath != "" {
		return "MCP named pipes"
	}
	return "MCP stdio"
}

func toolNames(result *mcpsdk.ListToolsResult) []string {
	if result == nil {
		return nil
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		if tool != nil {
			names = append(names, tool.Name)
		}
	}
	sort.Strings(names)
	return names
}

func requireTools(got, required []string) error {
	present := map[string]bool{}
	for _, name := range got {
		present[name] = true
	}
	var missing []string
	for _, name := range required {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("mcp server missing required tools: %s", strings.Join(missing, ", "))
	}
	return nil
}

func callAndDecode[T any](ctx context.Context, session mcpSession, name string, args map[string]any) (T, error) {
	var zero T
	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return zero, fmt.Errorf("call %s: %w", name, err)
	}
	if result == nil {
		return zero, fmt.Errorf("call %s: nil result", name)
	}
	if result.IsError {
		return zero, fmt.Errorf("call %s: tool returned error: %s", name, contentText(result.Content))
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return zero, fmt.Errorf("call %s: marshal structured content: %w", name, err)
	}
	if len(data) == 0 || string(data) == "null" {
		return zero, fmt.Errorf("call %s: missing structured content", name)
	}
	if err := json.Unmarshal(data, &zero); err != nil {
		return zero, fmt.Errorf("call %s: decode structured content: %w", name, err)
	}
	return zero, nil
}

func contentText(content []mcpsdk.Content) string {
	if len(content) == 0 {
		return "<empty>"
	}
	data, err := json.Marshal(content)
	if err != nil {
		return "<unprintable>"
	}
	return string(data)
}

func summarizeEntities(out operatorListEntitiesOutput) string {
	if len(out.Entities) == 0 {
		return "entities: none"
	}
	lines := make([]string, 0, len(out.Entities)+1)
	if out.Operation != "" {
		lines = append(lines, "operation: "+out.Operation)
	}
	for _, entity := range out.Entities {
		lines = append(lines, fmt.Sprintf("- %s (%s, agent=%t, chain=%s)", entity.ID, entity.Kind, entity.Agent, fallback(entity.ActiveChain, "<none>")))
	}
	return strings.Join(lines, "\n")
}

func summarizeOperations(operations []operationOutput) string {
	if len(operations) == 0 {
		return "operations: none"
	}
	lines := make([]string, 0, len(operations))
	for _, operation := range operations {
		lines = append(lines, fmt.Sprintf("- %s: targets=%d chains=%d", operation.Name, len(operation.Targets), len(operation.Chains)))
	}
	return strings.Join(lines, "\n")
}

func summarizeSnapshot(out workspaceSnapshotOutput, expectedOperation, expectedChain string) string {
	operation := findOperation(out.Operations, expectedOperation)
	if operation == nil && len(out.Operations) == 1 {
		operation = &out.Operations[0]
	}
	if operation == nil {
		return fmt.Sprintf("active_operation: %s\nactive_chain: %s\noperation %q not found", out.ActiveOperation, out.ActiveChain, expectedOperation)
	}
	chain := findChain(operation.Chains, expectedChain)
	if chain == nil && len(operation.Chains) == 1 {
		chain = &operation.Chains[0]
	}
	if chain == nil {
		return fmt.Sprintf("operation: %s\ntargets: %s\nchain %q not found", operation.Name, strings.Join(operation.Targets, ", "), expectedChain)
	}

	lines := []string{
		"active_operation: " + fallback(out.ActiveOperation, "<none>"),
		"active_chain: " + fallback(out.ActiveChain, "<none>"),
		"operation: " + operation.Name,
		"chain: " + chain.Name,
		"targets: " + fallback(strings.Join(operation.Targets, ", "), "<none>"),
		fmt.Sprintf("steps: %d", len(chain.Steps)),
	}
	for _, step := range chain.Steps {
		lines = append(lines, fmt.Sprintf("- %s %s", step.ID, step.ModuleID))
	}
	if len(chain.Config) > 0 {
		lines = append(lines, "config: "+summarizeStringMap(chain.Config))
	}
	return strings.Join(lines, "\n")
}

func summarizeThrow(out throwStartOutput) string {
	lines := []string{
		"operation: " + fallback(out.Operation, "<daemon default>"),
		"throw_id: " + fallback(out.ThrowID, "<none>"),
		"chain: " + out.Chain,
		"targets: " + fallback(strings.Join(out.Targets, ", "), "<none>"),
	}
	for _, result := range out.Results {
		lines = append(lines, fmt.Sprintf("- %s %s -> %s", result.ModuleID, result.Target, result.State))
		if result.Summary != "" {
			lines = append(lines, "  summary: "+result.Summary)
		}
		for _, session := range result.Sessions {
			lines = append(lines, fmt.Sprintf("  session: %s %s %s", session.ID, session.Kind, session.State))
			if session.Name != "" {
				lines = append(lines, "  name: "+session.Name)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func summarizePayloadCommands(out payloadCommandListOutput) string {
	lines := []string{
		fmt.Sprintf("payload: %s %s", out.Payload.Handle, out.Payload.Endpoint),
	}
	for _, command := range out.Commands {
		effect := "read"
		if command.Destructive {
			effect = "write"
		}
		lines = append(lines, fmt.Sprintf("- %s (%s) %s", command.Name, effect, command.Summary))
	}
	return strings.Join(lines, "\n")
}

func summarizePayloadCommandResult(out payloadCommandResult) string {
	lines := []string{
		"command: " + out.Command,
		"summary: " + out.Summary,
	}
	if strings.TrimSpace(out.Stdout) != "" {
		lines = append(lines, "stdout: "+strings.TrimSpace(out.Stdout))
	}
	if artifactID := out.Fields["artifactId"]; artifactID != "" {
		lines = append(lines, "artifact: "+artifactID)
	}
	if artifactPath := out.Fields["artifactPath"]; artifactPath != "" {
		lines = append(lines, "path: "+artifactPath)
	}
	return strings.Join(lines, "\n")
}

func findOperation(operations []operationOutput, name string) *operationOutput {
	for i := range operations {
		if operations[i].Name == name {
			return &operations[i]
		}
	}
	return nil
}

func findChain(chains []chainOutput, name string) *chainOutput {
	for i := range chains {
		if chains[i].Name == name {
			return &chains[i]
		}
	}
	return nil
}

func summarizeStringMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ", ")
}

func fallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type transcriptRenderer struct {
	out        io.Writer
	color      bool
	delay      time.Duration
	tokenDelay time.Duration
	title      string
	status     []string
	prompt     string
	blocks     []renderBlock
	styles     transcriptStyles
}

type renderBlock struct {
	kind      string
	label     string
	text      string
	streaming bool
}

type transcriptStyles struct {
	screen         lipgloss.Style
	header         lipgloss.Style
	title          lipgloss.Style
	status         lipgloss.Style
	userLabel      lipgloss.Style
	assistantLabel lipgloss.Style
	toolLabel      lipgloss.Style
	userText       lipgloss.Style
	assistantText  lipgloss.Style
	toolText       lipgloss.Style
	toolPanel      lipgloss.Style
	promptPanel    lipgloss.Style
	promptLabel    lipgloss.Style
	promptText     lipgloss.Style
	muted          lipgloss.Style
}

const (
	minTranscriptWidth  = 64
	minTranscriptHeight = 24
	fallbackWidth       = 88
	fallbackHeight      = 36
)

func newTranscriptRenderer(out io.Writer, color bool, delay, tokenDelay time.Duration, prompt string) transcriptRenderer {
	return transcriptRenderer{
		out:        out,
		color:      color,
		delay:      delay,
		tokenDelay: tokenDelay,
		prompt:     prompt,
		styles:     newTranscriptStyles(color),
	}
}

func newTranscriptStyles(color bool) transcriptStyles {
	styles := transcriptStyles{
		screen:         lipgloss.NewStyle(),
		header:         lipgloss.NewStyle().Padding(0, 1),
		title:          lipgloss.NewStyle().Bold(true),
		status:         lipgloss.NewStyle(),
		userLabel:      lipgloss.NewStyle().Bold(true),
		assistantLabel: lipgloss.NewStyle().Bold(true),
		toolLabel:      lipgloss.NewStyle().Bold(true),
		userText:       lipgloss.NewStyle(),
		assistantText:  lipgloss.NewStyle(),
		toolText:       lipgloss.NewStyle(),
		toolPanel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1),
		promptPanel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1),
		promptLabel: lipgloss.NewStyle().Bold(true),
		promptText:  lipgloss.NewStyle(),
		muted:       lipgloss.NewStyle().Faint(true),
	}
	if !color {
		return styles
	}
	return transcriptStyles{
		screen: styles.screen.
			Foreground(lipgloss.Color("#e7edf4")).
			Background(lipgloss.Color("#080b10")),
		header: styles.header.
			Foreground(lipgloss.Color("#f8fbff")).
			Background(lipgloss.Color("#171c25")),
		title: styles.title.
			Foreground(lipgloss.Color("#00e5ff")),
		status: styles.status.
			Foreground(lipgloss.Color("#aab6c4")),
		userLabel: styles.userLabel.
			Foreground(lipgloss.Color("#58a6ff")),
		assistantLabel: styles.assistantLabel.
			Foreground(lipgloss.Color("#7ee787")),
		toolLabel: styles.toolLabel.
			Foreground(lipgloss.Color("#ffd166")),
		userText: styles.userText.
			Foreground(lipgloss.Color("#d7e4f4")),
		assistantText: styles.assistantText.
			Foreground(lipgloss.Color("#e7edf4")),
		toolText: styles.toolText.
			Foreground(lipgloss.Color("#d8e1ea")),
		toolPanel: styles.toolPanel.
			Foreground(lipgloss.Color("#d8e1ea")).
			BorderForeground(lipgloss.Color("#3f8cff")),
		promptPanel: styles.promptPanel.
			Foreground(lipgloss.Color("#f2f7ff")).
			BorderForeground(lipgloss.Color("#ff2bd6")),
		promptLabel: styles.promptLabel.
			Foreground(lipgloss.Color("#ff2bd6")),
		promptText: styles.promptText.
			Foreground(lipgloss.Color("#00e5ff")),
		muted: styles.muted.
			Foreground(lipgloss.Color("#8492a6")),
	}
}

func (r *transcriptRenderer) header(title string, lines []string) {
	r.title = title
	r.status = append([]string(nil), lines...)
	r.draw()
	r.pause()
}

func (r *transcriptRenderer) user(text string) {
	r.block("user", "user", text)
}

func (r *transcriptRenderer) assistant(text string) {
	if r.tokenDelay <= 0 {
		r.block("assistant", "assistant", text)
		return
	}
	r.blocks = append(r.blocks, renderBlock{kind: "assistant", label: "assistant", streaming: true})
	index := len(r.blocks) - 1
	r.draw()
	for _, token := range streamTokens(text) {
		r.blocks[index].text += token
		r.draw()
		time.Sleep(r.tokenDelay)
	}
	r.blocks[index].streaming = false
	r.draw()
	r.pause()
}

func (r *transcriptRenderer) tool(name, text string) {
	r.block("tool", "tool: "+name, text)
}

func (r *transcriptRenderer) block(kind, label, text string) {
	r.blocks = append(r.blocks, renderBlock{kind: kind, label: label, text: text})
	r.draw()
	r.pause()
}

func (r *transcriptRenderer) draw() {
	width, height := terminalSize(r.out)
	header := r.renderHeader(width)
	prompt := r.renderPrompt(width)
	chatHeight := height - lipgloss.Height(header) - lipgloss.Height(prompt)
	if chatHeight < 6 {
		chatHeight = 6
	}
	chat := r.renderChat(width, chatHeight)
	body := strings.Join([]string{header, chat, prompt}, "\n")
	screen := r.styles.screen.Width(width).Height(height).Render(body)
	r.printf("\x1b[?25l\x1b[H\x1b[2J%s", screen)
}

func terminalSize(out io.Writer) (int, int) {
	width, height := fallbackWidth, fallbackHeight
	if file, ok := out.(interface{ Fd() uintptr }); ok {
		if gotWidth, gotHeight, err := term.GetSize(file.Fd()); err == nil {
			if gotWidth > 0 {
				width = gotWidth
			}
			if gotHeight > 0 {
				height = gotHeight
			}
		}
	}
	if width < minTranscriptWidth {
		width = minTranscriptWidth
	}
	if height < minTranscriptHeight {
		height = minTranscriptHeight
	}
	return width, height
}

func (r *transcriptRenderer) renderHeader(width int) string {
	title := r.styles.title.Render("✦ " + fallback(r.title, "Mock Codex Agent"))
	right := r.styles.muted.Render("mock-codex · MCP operator")
	line := title
	if room := width - lipgloss.Width(title) - lipgloss.Width(right) - 4; room > 0 {
		line += strings.Repeat(" ", room) + right
	}
	lines := []string{line}
	for _, statusLine := range packLines(r.status, width-2) {
		lines = append(lines, r.styles.status.Render(statusLine))
	}
	return r.styles.header.Width(width).Render(strings.Join(lines, "\n"))
}

func (r *transcriptRenderer) renderChat(width, height int) string {
	contentWidth := width - 4
	if contentWidth < 40 {
		contentWidth = width - 2
	}
	var lines []string
	for _, block := range r.blocks {
		lines = append(lines, r.renderBlock(block, contentWidth)...)
		lines = append(lines, "")
	}
	if len(lines) == 0 {
		lines = []string{r.styles.muted.Render("waiting for MCP transcript...")}
	}
	if len(lines) > height {
		lines = lines[len(lines)-height:]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return lipgloss.NewStyle().Width(width).Height(height).Padding(0, 1).Render(strings.Join(lines, "\n"))
}

func (r *transcriptRenderer) renderBlock(block renderBlock, width int) []string {
	switch block.kind {
	case "tool":
		return r.renderToolBlock(block, width)
	case "user":
		return r.renderMessageBlock(block, r.styles.userLabel, r.styles.userText, width)
	default:
		return r.renderMessageBlock(block, r.styles.assistantLabel, r.styles.assistantText, width)
	}
}

func (r *transcriptRenderer) renderMessageBlock(block renderBlock, labelStyle, textStyle lipgloss.Style, width int) []string {
	lines := []string{labelStyle.Render(block.label)}
	text := block.text
	if block.streaming {
		text += "▌"
	}
	for _, line := range wrapText(text, width-2) {
		lines = append(lines, textStyle.Render("  "+line))
	}
	return lines
}

func (r *transcriptRenderer) renderToolBlock(block renderBlock, width int) []string {
	bodyWidth := width - 6
	if bodyWidth < 24 {
		bodyWidth = width
	}
	bodyLines := append([]string{r.styles.toolLabel.Render(block.label)}, wrapText(block.text, bodyWidth)...)
	body := strings.Join(bodyLines, "\n")
	panel := r.styles.toolPanel.Width(width).Render(r.styles.toolText.Render(body))
	return strings.Split(panel, "\n")
}

func (r *transcriptRenderer) renderPrompt(width int) string {
	prompt := "> " + fallback(r.prompt, "Throw the configured mock exploit through Hovel MCP")
	bodyWidth := width - 8
	if bodyWidth < 24 {
		bodyWidth = width - 2
	}
	lines := append([]string{r.styles.promptLabel.Render("prompt")}, wrapText(prompt, bodyWidth)...)
	body := strings.Join(lines, "\n")
	return r.styles.promptPanel.Width(width - 2).Render(r.styles.promptText.Render(body))
}

func (r *transcriptRenderer) printf(format string, args ...any) {
	fmt.Fprintf(r.out, format, args...)
}

func (r *transcriptRenderer) pause() {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
}

func wrapText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			out = append(out, "")
			continue
		}
		for len(line) > width {
			cut := strings.LastIndex(line[:width+1], " ")
			if cut <= 0 {
				break
			}
			out = append(out, strings.TrimSpace(line[:cut]))
			line = strings.TrimSpace(line[cut:])
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func packLines(lines []string, width int) []string {
	if width < 1 {
		width = 1
	}
	var packed []string
	var current string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		next := line
		if current != "" {
			next = current + "  ·  " + line
		}
		if current != "" && lipgloss.Width(next) > width {
			packed = append(packed, current)
			current = line
			continue
		}
		current = next
	}
	if current != "" {
		packed = append(packed, current)
	}
	return packed
}

func streamTokens(text string) []string {
	if text == "" {
		return []string{""}
	}
	var tokens []string
	var b strings.Builder
	for _, r := range text {
		b.WriteRune(r)
		switch r {
		case ' ', '\n', '.', ',', ';', ':', '!', '?', ')':
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}
	if b.Len() > 0 {
		tokens = append(tokens, b.String())
	}
	return tokens
}

type operatorEntity struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"displayName"`
	Agent        bool     `json:"agent"`
	Operation    string   `json:"operation,omitempty"`
	ActiveChain  string   `json:"activeChain,omitempty"`
	ConnectedAt  string   `json:"connectedAt"`
	LastSeenAt   string   `json:"lastSeenAt"`
	Capabilities []string `json:"capabilities,omitempty"`
	PolicyTags   []string `json:"policyTags,omitempty"`
}

type operatorIdentityOutput struct {
	Entity operatorEntity `json:"entity"`
}

type operatorListEntitiesOutput struct {
	Operation string           `json:"operation,omitempty"`
	Entities  []operatorEntity `json:"entities"`
}

type operationListOutput struct {
	ActiveOperation string            `json:"activeOperation,omitempty"`
	ActiveChain     string            `json:"activeChain,omitempty"`
	Operations      []operationOutput `json:"operations"`
}

type workspaceSnapshotOutput struct {
	Entity          operatorEntity    `json:"entity"`
	ActiveOperation string            `json:"activeOperation,omitempty"`
	ActiveChain     string            `json:"activeChain,omitempty"`
	Operations      []operationOutput `json:"operations"`
}

type throwStartOutput struct {
	Operation string           `json:"operation,omitempty"`
	ThrowID   string           `json:"throwId,omitempty"`
	Chain     string           `json:"chain"`
	Targets   []string         `json:"targets"`
	Results   []throwRunOutput `json:"results"`
}

type throwRunOutput struct {
	RunID    string               `json:"runId"`
	ModuleID string               `json:"moduleId"`
	Target   string               `json:"target"`
	State    string               `json:"state"`
	Summary  string               `json:"summary"`
	Sessions []throwSessionOutput `json:"sessions"`
}

type throwSessionOutput struct {
	ID           string   `json:"id"`
	RunID        string   `json:"runId"`
	ModuleID     string   `json:"moduleId"`
	Target       string   `json:"target"`
	Name         string   `json:"name,omitempty"`
	Kind         string   `json:"kind"`
	State        string   `json:"state"`
	Transport    string   `json:"transport"`
	Capabilities []string `json:"capabilities"`
}

type payloadCommandListOutput struct {
	Payload  installedPayloadOutput `json:"payload"`
	Commands []payloadCommand       `json:"commands"`
}

type payloadCommandCallOutput struct {
	Payload installedPayloadOutput `json:"payload"`
	Result  payloadCommandResult   `json:"result"`
}

type installedPayloadOutput struct {
	Handle   string `json:"handle"`
	Provider string `json:"provider"`
	Target   string `json:"target"`
	State    string `json:"state"`
	Endpoint string `json:"endpoint"`
}

type payloadCommand struct {
	Name        string `json:"name"`
	Summary     string `json:"summary,omitempty"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	Destructive bool   `json:"destructive,omitempty"`
}

type payloadCommandResult struct {
	Command string            `json:"command"`
	Summary string            `json:"summary,omitempty"`
	Stdout  string            `json:"stdout,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type operationOutput struct {
	Name    string        `json:"name"`
	Targets []string      `json:"targets,omitempty"`
	Chains  []chainOutput `json:"chains"`
}

type chainOutput struct {
	Name   string            `json:"name"`
	Steps  []stepOutput      `json:"steps,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

type stepOutput struct {
	ID       string `json:"ID,omitempty"`
	ModuleID string `json:"ModuleID,omitempty"`
	StepID   string `json:"stepId,omitempty"`
}
