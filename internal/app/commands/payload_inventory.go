package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	workspacepath "github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

const (
	PayloadStateInstalled   = "installed"
	PayloadStateConnected   = "connected"
	PayloadStateUnreachable = "unreachable"
	PayloadStateRemoved     = "removed"
)

type PayloadProviderRecord struct {
	ProviderID    string         `json:"providerId,omitempty"`
	Schema        string         `json:"schema,omitempty"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
	Descriptor    map[string]any `json:"descriptor,omitempty"`
}

type InstalledPayloadDescriptor struct {
	Provider                 string                 `json:"provider"`
	PayloadID                string                 `json:"payloadId"`
	PayloadVersion           string                 `json:"payloadVersion,omitempty"`
	Target                   string                 `json:"target"`
	TargetID                 string                 `json:"targetId,omitempty"`
	State                    string                 `json:"state,omitempty"`
	Transport                string                 `json:"transport,omitempty"`
	Endpoint                 string                 `json:"endpoint,omitempty"`
	InstanceKey              string                 `json:"instanceKey,omitempty"`
	StampID                  string                 `json:"stampId,omitempty"`
	ArtifactIDs              []string               `json:"artifactIds,omitempty"`
	SupportsReconnect        bool                   `json:"supportsReconnect,omitempty"`
	SupportsMultipleSessions bool                   `json:"supportsMultipleSessions,omitempty"`
	Reconnect                *PayloadProviderRecord `json:"reconnect,omitempty"`
	Cleanup                  *PayloadProviderRecord `json:"cleanup,omitempty"`
	Metadata                 map[string]string      `json:"metadata,omitempty"`
}

type InstalledPayloadRecord struct {
	ID                       string                 `json:"id"`
	Handle                   string                 `json:"handle"`
	Workspace                string                 `json:"workspace"`
	Provider                 string                 `json:"provider"`
	PayloadID                string                 `json:"payloadId"`
	PayloadVersion           string                 `json:"payloadVersion,omitempty"`
	Target                   string                 `json:"target"`
	TargetID                 string                 `json:"targetId,omitempty"`
	State                    string                 `json:"state"`
	Transport                string                 `json:"transport,omitempty"`
	Endpoint                 string                 `json:"endpoint,omitempty"`
	InstanceKey              string                 `json:"instanceKey,omitempty"`
	StampID                  string                 `json:"stampId,omitempty"`
	ArtifactIDs              []string               `json:"artifactIds,omitempty"`
	SupportsReconnect        bool                   `json:"supportsReconnect"`
	SupportsMultipleSessions bool                   `json:"supportsMultipleSessions"`
	Reconnect                *PayloadProviderRecord `json:"reconnect,omitempty"`
	Cleanup                  *PayloadProviderRecord `json:"cleanup,omitempty"`
	Operation                string                 `json:"operation,omitempty"`
	Chain                    string                 `json:"chain,omitempty"`
	ThrowID                  string                 `json:"throwId,omitempty"`
	RunID                    string                 `json:"runId,omitempty"`
	CreatedAt                string                 `json:"createdAt"`
	UpdatedAt                string                 `json:"updatedAt"`
	LastSeenAt               string                 `json:"lastSeenAt,omitempty"`
	Metadata                 map[string]string      `json:"metadata,omitempty"`
}

type InstalledPayloadFilter struct {
	IncludeRemoved bool
	State          string
}

type InstalledPayloadEvent struct {
	ID        string            `json:"id"`
	PayloadID string            `json:"payloadId"`
	Handle    string            `json:"handle"`
	Workspace string            `json:"workspace"`
	Type      string            `json:"type"`
	From      string            `json:"from,omitempty"`
	To        string            `json:"to,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Message   string            `json:"message,omitempty"`
	CreatedAt string            `json:"createdAt"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type PayloadCommand = run.PayloadCommand
type PayloadCommandArgument = run.PayloadCommandArgument
type PayloadCommandRequest = run.PayloadCommandRequest
type PayloadCommandResult = run.PayloadCommandResult

type PayloadInspectPayload struct {
	Record InstalledPayloadRecord  `json:"record"`
	Events []InstalledPayloadEvent `json:"events,omitempty"`
}

type PayloadRepository interface {
	RecordInstalledPayload(context.Context, InstalledPayloadRecord) (InstalledPayloadRecord, error)
	ListInstalledPayloads(context.Context, string, InstalledPayloadFilter) ([]InstalledPayloadRecord, error)
	GetInstalledPayload(context.Context, string, string) (InstalledPayloadRecord, error)
	UpdateInstalledPayloadState(context.Context, string, string, string, string) (InstalledPayloadRecord, error)
	ListInstalledPayloadEvents(context.Context, string, string) ([]InstalledPayloadEvent, error)
}

type AvailablePayload struct {
	Provider     string   `json:"provider"`
	PayloadID    string   `json:"payloadId"`
	Name         string   `json:"name,omitempty"`
	Version      string   `json:"version,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Arch         string   `json:"arch,omitempty"`
	Formats      []string `json:"formats,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Transport    string   `json:"transport,omitempty"`
}

type PayloadProviderService interface {
	ListAvailablePayloads(context.Context) ([]AvailablePayload, error)
	ConnectInstalledPayload(context.Context, InstalledPayloadRecord) (SessionRef, error)
	CleanupInstalledPayload(context.Context, InstalledPayloadRecord, string) error
	RefreshInstalledPayload(context.Context, InstalledPayloadRecord) (InstalledPayloadRecord, error)
	ListPayloadCommands(context.Context, InstalledPayloadRecord) ([]PayloadCommand, error)
	RunPayloadCommand(context.Context, InstalledPayloadRecord, PayloadCommandRequest) (PayloadCommandResult, error)
}

func payloadsAvailableHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		payloads, err := listAvailablePayloads(ctx, runtime)
		if err != nil {
			return Result{}, err
		}
		if len(payloads) == 0 {
			return Result{Human: "No payloads available", JSON: payloads}, nil
		}
		return Result{Human: availablePayloadLines(payloads), JSON: payloads}, nil
	}
}

func payloadsInstalledHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		records, err := runtime.Payloads.ListInstalledPayloads(ctx, payloadWorkspace(invocation), InstalledPayloadFilter{
			IncludeRemoved: invocation.Flag("all"),
			State:          invocation.Option("state"),
		})
		if err != nil {
			return Result{}, err
		}
		if len(records) == 0 {
			return Result{Human: "No installed payloads\nUse payloads list for provider-buildable payloads, or chain add squatter@v0.1.0 to install Squatter during a throw.", JSON: records}, nil
		}
		return Result{Human: installedPayloadLines(records), JSON: records}, nil
	}
}

func payloadsInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		record, err := runtime.Payloads.GetInstalledPayload(ctx, payloadWorkspace(invocation), invocation.Positional("payload"))
		if err != nil {
			return Result{}, err
		}
		lines := installedPayloadInspectLines(record)
		if invocation.Flag("events") {
			events, err := runtime.Payloads.ListInstalledPayloadEvents(ctx, payloadWorkspace(invocation), record.Handle)
			if err != nil {
				return Result{}, err
			}
			lines = append(lines, "")
			lines = append(lines, installedPayloadEventLines(events)...)
			return Result{
				Human: strings.Join(lines, "\n"),
				JSON:  PayloadInspectPayload{Record: record, Events: events},
			}, nil
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: record}, nil
	}
}

func payloadsConnectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		if runtime.PayloadProviders == nil {
			return Result{}, fmt.Errorf("payload provider service is not configured")
		}
		record, err := runtime.Payloads.GetInstalledPayload(ctx, payloadWorkspace(invocation), invocation.Positional("payload"))
		if err != nil {
			return Result{}, err
		}
		if !record.SupportsReconnect || record.Reconnect == nil {
			return Result{}, fmt.Errorf("payload %s does not support reconnect", record.Handle)
		}
		session, err := runtime.PayloadProviders.ConnectInstalledPayload(ctx, record)
		if err != nil {
			_, _ = runtime.Payloads.UpdateInstalledPayloadState(ctx, payloadWorkspace(invocation), record.Handle, PayloadStateUnreachable, err.Error())
			return Result{}, err
		}
		if session.InstalledPayloadID == "" {
			session.InstalledPayloadID = record.Handle
		}
		if _, err := runtime.Payloads.UpdateInstalledPayloadState(ctx, payloadWorkspace(invocation), record.Handle, PayloadStateConnected, "session connected"); err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Session opened: %s payload=%s target=%s", session.ID, record.Handle, record.Target),
			JSON:  session,
		}, nil
	}
}

func payloadsCleanupHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		if runtime.PayloadProviders == nil {
			return Result{}, fmt.Errorf("payload provider service is not configured")
		}
		record, err := runtime.Payloads.GetInstalledPayload(ctx, payloadWorkspace(invocation), invocation.Positional("payload"))
		if err != nil {
			return Result{}, err
		}
		reason := invocation.Option("reason")
		if reason == "" {
			reason = "operator cleanup"
		}
		if err := runtime.PayloadProviders.CleanupInstalledPayload(ctx, record, reason); err != nil {
			return Result{}, err
		}
		removed, err := runtime.Payloads.UpdateInstalledPayloadState(ctx, payloadWorkspace(invocation), record.Handle, PayloadStateRemoved, reason)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Payload cleaned up: %s", removed.Handle),
			JSON:  removed,
		}, nil
	}
}

func payloadsMarkRemovedHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		reason := invocation.Option("reason")
		if reason == "" {
			reason = "operator marked removed"
		}
		record, err := runtime.Payloads.UpdateInstalledPayloadState(ctx, payloadWorkspace(invocation), invocation.Positional("payload"), PayloadStateRemoved, reason)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Payload marked removed: %s", record.Handle),
			JSON:  record,
		}, nil
	}
}

func payloadsRefreshHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		if runtime.PayloadProviders == nil {
			return Result{}, fmt.Errorf("payload provider service is not configured")
		}
		record, err := runtime.Payloads.GetInstalledPayload(ctx, payloadWorkspace(invocation), invocation.Positional("payload"))
		if err != nil {
			return Result{}, err
		}
		refreshed, err := runtime.PayloadProviders.RefreshInstalledPayload(ctx, record)
		if err != nil {
			_, _ = runtime.Payloads.UpdateInstalledPayloadState(ctx, payloadWorkspace(invocation), record.Handle, PayloadStateUnreachable, err.Error())
			return Result{}, err
		}
		if refreshed.ID == "" {
			refreshed.ID = record.ID
		}
		if refreshed.Handle == "" {
			refreshed.Handle = record.Handle
		}
		if refreshed.Workspace == "" {
			refreshed.Workspace = record.Workspace
		}
		refreshed, err = runtime.Payloads.RecordInstalledPayload(ctx, refreshed)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Payload refreshed: %s %s", refreshed.Handle, refreshed.State),
			JSON:  refreshed,
		}, nil
	}
}

func payloadsRegisterSquatterHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		target := strings.TrimSpace(invocation.Positional("target"))
		host := strings.TrimSpace(invocation.Option("host"))
		if host == "" {
			host = target
		}
		port := strings.TrimSpace(invocation.Option("port"))
		if port == "" {
			port = "9100"
		}
		if parsed, err := strconv.Atoi(port); err != nil || parsed < 1 || parsed > 65535 {
			return Result{}, fmt.Errorf("port must be a TCP port: %q", port)
		}
		endpoint := host + ":" + port
		record, err := runtime.Payloads.RecordInstalledPayload(ctx, InstalledPayloadRecord{
			Workspace:                payloadWorkspace(invocation),
			Provider:                 "squatter",
			PayloadID:                "squatter/windows/x86/windows-7/tcp-bind/pe-exe",
			PayloadVersion:           "v0.1.0",
			Target:                   target,
			State:                    PayloadStateInstalled,
			Transport:                "tcp-bind",
			Endpoint:                 endpoint,
			InstanceKey:              "squatter:" + endpoint,
			SupportsReconnect:        true,
			SupportsMultipleSessions: true,
			Reconnect: &PayloadProviderRecord{
				ProviderID:    "squatter",
				Schema:        "squatter.tcp_bind.reconnect",
				SchemaVersion: "1",
				Descriptor: map[string]any{
					"target":    target,
					"host":      host,
					"port":      port,
					"transport": "tcp-bind",
				},
			},
			Cleanup: &PayloadProviderRecord{
				ProviderID:    "squatter",
				Schema:        "squatter.cleanup",
				SchemaVersion: "1",
				Descriptor:    map[string]any{"transport": "tcp-bind"},
			},
			Metadata: map[string]string{"source": "manual"},
		})
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Payload registered: %s squatter %s", record.Handle, endpoint),
			JSON:  record,
		}, nil
	}
}

func payloadsCommandsHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Payloads == nil {
			return Result{}, fmt.Errorf("payload repository is not configured")
		}
		if runtime.PayloadProviders == nil {
			return Result{}, fmt.Errorf("payload provider service is not configured")
		}
		record, err := runtime.Payloads.GetInstalledPayload(ctx, payloadWorkspace(invocation), invocation.Positional("payload"))
		if err != nil {
			return Result{}, err
		}
		commands, err := runtime.PayloadProviders.ListPayloadCommands(ctx, record)
		if err != nil {
			return Result{}, err
		}
		return Result{Human: payloadCommandLines(commands), JSON: commands}, nil
	}
}

func payloadsCallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		return runPayloadProviderCall(ctx, runtime, invocation, invocation.Positional("capability"), payloadCommandRequestFromGenericInvocation)
	}
}

func payloadsRunCommandHandler(runtime Runtime, command string) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		return runPayloadProviderCall(ctx, runtime, invocation, command, payloadCommandRequestFromLegacyInvocation)
	}
}

func runPayloadProviderCall(ctx context.Context, runtime Runtime, invocation Invocation, command string, requestFromInvocation func(string, Invocation) (PayloadCommandRequest, error)) (Result, error) {
	if runtime.Payloads == nil {
		return Result{}, fmt.Errorf("payload repository is not configured")
	}
	if runtime.PayloadProviders == nil {
		return Result{}, fmt.Errorf("payload provider service is not configured")
	}
	workspacePath := payloadWorkspace(invocation)
	record, err := runtime.Payloads.GetInstalledPayload(ctx, workspacePath, invocation.Positional("payload"))
	if err != nil {
		return Result{}, err
	}
	req, err := requestFromInvocation(command, invocation)
	if err != nil {
		return Result{}, err
	}
	result, err := runtime.PayloadProviders.RunPayloadCommand(ctx, record, req)
	if err != nil {
		_, _ = runtime.Payloads.UpdateInstalledPayloadState(ctx, workspacePath, record.Handle, PayloadStateUnreachable, err.Error())
		return Result{}, err
	}
	if len(result.Artifacts) > 0 && runtime.Artifacts != nil {
		result, err = materializePayloadCommandArtifacts(ctx, runtime, workspacePath, record, result)
		if err != nil {
			return Result{}, err
		}
	}
	return Result{Human: payloadCommandResultHuman(result), JSON: result}, nil
}

func payloadCommandRequestFromLegacyInvocation(command string, invocation Invocation) (PayloadCommandRequest, error) {
	req := PayloadCommandRequest{Command: command}
	switch command {
	case "getfile":
		req.Args = []string{invocation.Positional("remote")}
	case "putfile":
		path, err := filepath.Abs(invocation.Positional("local"))
		if err != nil {
			return PayloadCommandRequest{}, err
		}
		req.InputPath = path
		req.Args = []string{invocation.Positional("remote")}
	case "cmd":
		req.Args = []string{invocation.Positional("command")}
	default:
		return PayloadCommandRequest{}, fmt.Errorf("unsupported payload command %q", command)
	}
	return req, nil
}

func payloadCommandRequestFromGenericInvocation(command string, invocation Invocation) (PayloadCommandRequest, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return PayloadCommandRequest{}, fmt.Errorf("payload capability is required")
	}
	req := PayloadCommandRequest{
		Command:       command,
		Args:          invocation.OptionList("arg"),
		InputData:     invocation.Option("input-data"),
		InputEncoding: strings.TrimSpace(invocation.Option("input-encoding")),
	}
	inputFile := strings.TrimSpace(invocation.Option("input-file"))
	if inputFile != "" && req.InputData != "" {
		return PayloadCommandRequest{}, fmt.Errorf("--input-file and --input-data cannot be used together")
	}
	if inputFile != "" {
		path, err := filepath.Abs(inputFile)
		if err != nil {
			return PayloadCommandRequest{}, err
		}
		req.InputPath = path
	}
	if req.InputData != "" && req.InputEncoding == "" {
		req.InputEncoding = "utf-8"
	}
	config, err := parsePayloadCallConfig(invocation.OptionList("set"))
	if err != nil {
		return PayloadCommandRequest{}, err
	}
	if len(config) > 0 {
		req.Config = config
	}
	return req, nil
}

func parsePayloadCallConfig(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	config := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("--set must use key=value: %q", value)
		}
		config[key] = strings.TrimSpace(val)
	}
	return config, nil
}

func materializePayloadCommandArtifacts(ctx context.Context, runtime Runtime, workspacePath string, record InstalledPayloadRecord, result PayloadCommandResult) (PayloadCommandResult, error) {
	if result.Fields == nil {
		result.Fields = map[string]string{}
	}
	for index, artifact := range result.Artifacts {
		materialized, err := runtime.Artifacts.MaterializeArtifact(ctx, ArtifactMaterialization{
			Workspace: workspacePath,
			ThrowID:   "payload-command",
			RunID:     "payload-" + record.Handle + "-" + result.Command,
			ModuleID:  "payload/" + record.Provider,
			Target:    record.Target,
			Artifact: Artifact{
				Name: artifact.Name,
				Kind: artifact.Kind,
				Data: artifact.Data,
				Path: artifact.Path,
			},
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return PayloadCommandResult{}, err
		}
		result.Artifacts[index].Data = ""
		result.Artifacts[index].Path = materialized.Path
		result.Fields["artifactId"] = materialized.ID
		result.Fields["artifactPath"] = materialized.Path
	}
	return result, nil
}

func listAvailablePayloads(ctx context.Context, runtime Runtime) ([]AvailablePayload, error) {
	if runtime.PayloadProviders != nil {
		payloads, err := runtime.PayloadProviders.ListAvailablePayloads(ctx)
		if err != nil {
			return nil, err
		}
		sortAvailablePayloads(payloads)
		return payloads, nil
	}
	db := moduleDB(runtime)
	var payloads []AvailablePayload
	for _, module := range db.ByType(modulecatalog.TypePayloadProvider) {
		payloads = append(payloads, AvailablePayload{
			Provider:  module.Name,
			PayloadID: module.ID,
			Name:      module.Name,
			Version:   module.Version,
		})
	}
	sortAvailablePayloads(payloads)
	return payloads, nil
}

func payloadWorkspace(invocation Invocation) string {
	return workspacepath.ResolvePath(invocation.Option("workspace"))
}

func availablePayloadLines(payloads []AvailablePayload) string {
	lines := []string{"PROVIDER                 PAYLOAD                                            TRANSPORT    FORMAT      CAPABILITIES"}
	for _, payload := range payloads {
		lines = append(lines, fmt.Sprintf("%-24s %-50s %-12s %-11s %s",
			displayValue(payload.Provider, "-"),
			payload.PayloadID,
			displayValue(payload.Transport, "-"),
			displayValue(strings.Join(payload.Formats, ","), "-"),
			displayValue(strings.Join(payload.Capabilities, ","), "-"),
		))
	}
	return strings.Join(lines, "\n")
}

func installedPayloadLines(records []InstalledPayloadRecord) string {
	lines := []string{"ID    STATE        PROVIDER       TARGET               TRANSPORT    ENDPOINT"}
	for _, record := range records {
		lines = append(lines, fmt.Sprintf("%-5s %-12s %-14s %-20s %-12s %s",
			record.Handle,
			record.State,
			record.Provider,
			record.Target,
			displayValue(record.Transport, "-"),
			displayValue(record.Endpoint, "-"),
		))
	}
	return strings.Join(lines, "\n")
}

func installedPayloadInspectLines(record InstalledPayloadRecord) []string {
	lines := []string{
		fmt.Sprintf("Payload %s", record.Handle),
		fmt.Sprintf("state      %s", record.State),
		fmt.Sprintf("provider   %s", record.Provider),
		fmt.Sprintf("payload    %s", record.PayloadID),
		fmt.Sprintf("target     %s", record.Target),
		fmt.Sprintf("transport  %s", displayValue(record.Transport, "-")),
		fmt.Sprintf("endpoint   %s", displayValue(record.Endpoint, "-")),
		fmt.Sprintf("reconnect  %t", record.SupportsReconnect),
		fmt.Sprintf("sessions   %t", record.SupportsMultipleSessions),
		fmt.Sprintf("throw      %s", displayValue(record.ThrowID, "-")),
		fmt.Sprintf("run        %s", displayValue(record.RunID, "-")),
	}
	if record.InstanceKey != "" {
		lines = append(lines, fmt.Sprintf("instance   %s", record.InstanceKey))
	}
	if record.StampID != "" {
		lines = append(lines, fmt.Sprintf("stamp      %s", record.StampID))
	}
	return lines
}

func installedPayloadEventLines(events []InstalledPayloadEvent) []string {
	if len(events) == 0 {
		return []string{"No payload events"}
	}
	lines := []string{"EVENTS", "TIME                           TYPE           FROM         TO           REASON"}
	for _, evt := range events {
		lines = append(lines, fmt.Sprintf("%-30s %-14s %-12s %-12s %s",
			evt.CreatedAt,
			evt.Type,
			displayValue(evt.From, "-"),
			displayValue(evt.To, "-"),
			displayValue(evt.Reason, "-"),
		))
	}
	return lines
}

func payloadCommandLines(commands []PayloadCommand) string {
	if len(commands) == 0 {
		return "No payload commands"
	}
	lines := []string{"COMMAND      EFFECT       SUMMARY"}
	for _, command := range commands {
		effect := "safe"
		if command.Destructive {
			effect = "destructive"
		} else if !command.ReadOnly {
			effect = "write"
		}
		lines = append(lines, fmt.Sprintf("%-12s %-12s %s", command.Name, effect, command.Summary))
	}
	return strings.Join(lines, "\n")
}

func payloadCommandResultHuman(result PayloadCommandResult) string {
	return commandResultHuman("Payload command", result)
}

func sessionCommandResultHuman(result PayloadCommandResult) string {
	return commandResultHuman("Session command", result)
}

func commandResultHuman(prefix string, result PayloadCommandResult) string {
	lines := []string{fmt.Sprintf("%s completed: %s", prefix, result.Command)}
	if result.Summary != "" {
		lines = append(lines, result.Summary)
	}
	if result.Stdout != "" {
		lines = append(lines, strings.TrimSpace(result.Stdout))
	}
	if artifactID := result.Fields["artifactId"]; artifactID != "" {
		lines = append(lines, "artifact "+artifactID+" "+result.Fields["artifactPath"])
	}
	return strings.Join(lines, "\n")
}

func sortAvailablePayloads(payloads []AvailablePayload) {
	sort.Slice(payloads, func(i, j int) bool {
		if payloads[i].Provider == payloads[j].Provider {
			return payloads[i].PayloadID < payloads[j].PayloadID
		}
		return payloads[i].Provider < payloads[j].Provider
	})
}

func cloneInstalledPayloadDescriptors(payloads []InstalledPayloadDescriptor) []InstalledPayloadDescriptor {
	out := make([]InstalledPayloadDescriptor, 0, len(payloads))
	for _, payload := range payloads {
		out = append(out, InstalledPayloadDescriptor{
			Provider:                 payload.Provider,
			PayloadID:                payload.PayloadID,
			PayloadVersion:           payload.PayloadVersion,
			Target:                   payload.Target,
			TargetID:                 payload.TargetID,
			State:                    payload.State,
			Transport:                payload.Transport,
			Endpoint:                 payload.Endpoint,
			InstanceKey:              payload.InstanceKey,
			StampID:                  payload.StampID,
			ArtifactIDs:              append([]string(nil), payload.ArtifactIDs...),
			SupportsReconnect:        payload.SupportsReconnect,
			SupportsMultipleSessions: payload.SupportsMultipleSessions,
			Reconnect:                clonePayloadProviderRecord(payload.Reconnect),
			Cleanup:                  clonePayloadProviderRecord(payload.Cleanup),
			Metadata:                 cloneStringMap(payload.Metadata),
		})
	}
	return out
}

func clonePayloadProviderRecord(record *PayloadProviderRecord) *PayloadProviderRecord {
	if record == nil {
		return nil
	}
	return &PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    cloneAnyMap(record.Descriptor),
	}
}
