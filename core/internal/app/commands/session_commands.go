package commands

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func sessionsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessions, err := client.ListSessions(ctx)
		if err != nil {
			return Result{}, err
		}
		if len(sessions) == 0 {
			return Result{Human: "No sessions", JSON: sessions}, nil
		}
		lines := []string{"ID                         KIND      STATE    TARGET        NAME"}
		for _, session := range sessions {
			lines = append(lines, fmt.Sprintf("%-26s %-9s %-8s %-13s %s", session.ID, session.Kind, session.State, session.Target, session.Name))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: sessions}, nil
	}
}

func sessionConnectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("session connect needs an interactive terminal; use hovel session connect %s or run hovel cli", invocation.Positional("session"))
	}
}

func sessionTailHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()

		options, err := sessionTailOptionsFromInvocation(invocation, 20)
		if err != nil {
			return Result{}, err
		}
		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		chunk, err := client.TailSession(ctx, sessionID, options)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Raw: chunk.Data,
			JSON: map[string]any{
				"sessionId": sessionID,
				"data":      string(chunk.Data),
				"closed":    chunk.Closed,
			},
		}, nil
	}
}

func sessionReadHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()

		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		var out []byte
		closed := false
		for {
			timeout := 75 * time.Millisecond
			if invocation.Flag("tail") {
				timeout = 250 * time.Millisecond
			}
			chunk, err := client.ReadSession(ctx, sessionID, timeout)
			if err != nil {
				return Result{}, err
			}
			if len(chunk.Data) > 0 {
				if invocation.Flag("tail") && !invocation.Flag("json") && invocation.Output != nil {
					if _, err := invocation.Output.Write(chunk.Data); err != nil {
						return Result{}, err
					}
				} else {
					out = append(out, chunk.Data...)
				}
			}
			if chunk.Closed {
				closed = true
				break
			}
			if !invocation.Flag("tail") && len(chunk.Data) == 0 {
				break
			}
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
		}

		if invocation.Flag("tail") && !invocation.Flag("json") && invocation.Output != nil {
			return Result{}, nil
		}
		payload := map[string]any{
			"sessionId": sessionID,
			"data":      string(out),
			"closed":    closed,
		}
		if invocation.Flag("json") {
			return Result{JSON: payload}, nil
		}
		return Result{
			Human: sessionReadHuman(sessionID, out, closed),
			JSON:  payload,
		}, nil
	}
}

func sessionReadHuman(sessionID string, data []byte, closed bool) string {
	status := "open"
	if closed {
		status = "closed"
	}
	stats := fmt.Sprintf("Session %s read %d %s (%s)", sessionID, len(data), pluralize("byte", len(data)), status)
	if len(data) == 0 {
		return "\n" + stats
	}
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text + "\n" + stats
}

func pluralize(noun string, count int) string {
	if count == 1 {
		return noun
	}
	return noun + "s"
}

func sessionTailOptionsFromInvocation(invocation Invocation, defaultLines int) (SessionTailOptions, error) {
	bytesValue := invocation.Option("bytes")
	linesValue := invocation.Option("lines")
	if bytesValue == "" {
		bytesValue = invocation.Option("history-bytes")
	}
	if linesValue == "" {
		linesValue = invocation.Option("history-lines")
	}
	if bytesValue != "" && linesValue != "" {
		return SessionTailOptions{}, fmt.Errorf("byte and line history limits are mutually exclusive")
	}
	var options SessionTailOptions
	switch {
	case bytesValue != "":
		count, err := parseSessionCount("bytes", bytesValue)
		if err != nil {
			return SessionTailOptions{}, err
		}
		options.MaxBytes = count
	case linesValue != "":
		count, err := parseSessionCount("lines", linesValue)
		if err != nil {
			return SessionTailOptions{}, err
		}
		options.MaxLines = count
	case defaultLines > 0:
		options.MaxLines = defaultLines
	}
	return options, nil
}

func parseSessionCount(name, value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	count, err := strconv.Atoi(value)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return count, nil
}

func sessionSendHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()

		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		payload := []byte(invocation.Positional("data"))
		switch {
		case invocation.Flag("no-newline") && invocation.Option("end") != "":
			return Result{}, fmt.Errorf("--no-newline and --end cannot be used together")
		case invocation.Option("end") != "":
			end, err := parseSessionTerminator(invocation.Option("end"))
			if err != nil {
				return Result{}, err
			}
			payload = append(payload, end...)
		case !invocation.Flag("no-newline"):
			payload = append(payload, '\n')
		}

		if err := client.WriteSession(ctx, sessionID, payload); err != nil {
			return Result{}, err
		}
		result := map[string]any{"sessionId": sessionID, "bytes": len(payload)}
		return Result{Human: fmt.Sprintf("Sent %d bytes to %s", len(payload), sessionID), JSON: result}, nil
	}
}

func sessionCloseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		if err := client.CloseSession(ctx, sessionID); err != nil {
			return Result{}, err
		}
		payload := map[string]string{"sessionId": sessionID, "status": "closed"}
		return Result{Human: fmt.Sprintf("Session closed: %s", sessionID), JSON: payload}, nil
	}
}

func sessionCommandsHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		commands, err := client.ListSessionCommands(ctx, sessionID, RunSessionCommandListRequest{})
		if err != nil {
			return Result{}, err
		}
		return Result{Human: payloadCommandLines(commands), JSON: commands}, nil
	}
}

func sessionCallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		client, closeClient, err := dialDaemonRunClient(ctx, runtime, invocation.Option("workspace"))
		if err != nil {
			return Result{}, err
		}
		defer closeClient()
		sessionID, err := resolveSessionID(ctx, client, invocation.Positional("session"))
		if err != nil {
			return Result{}, err
		}
		req, err := payloadCommandRequestFromGenericInvocation(invocation.Positional("capability"), invocation)
		if err != nil {
			return Result{}, err
		}
		result, err := client.RunSessionCommand(ctx, RunSessionCommandRunRequest{
			SessionID: sessionID,
			Request:   req,
		})
		if err != nil {
			return Result{}, err
		}
		return Result{Human: sessionCommandResultHuman(result), JSON: result}, nil
	}
}

func resolveSessionID(ctx context.Context, client RunClient, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	switch requested {
	case "latest", "@latest":
		sessions, err := client.ListSessions(ctx)
		if err != nil {
			return "", err
		}
		for i := len(sessions) - 1; i >= 0; i-- {
			session := sessions[i]
			if sessionIsActive(session) {
				return session.ID, nil
			}
		}
		if len(sessions) == 0 {
			return "", fmt.Errorf("no sessions available")
		}
		return "", fmt.Errorf("no active sessions available")
	default:
		return requested, nil
	}
}

func sessionIsActive(session SessionRef) bool {
	switch strings.ToLower(strings.TrimSpace(session.State)) {
	case "", "active", "open":
		return true
	default:
		return false
	}
}

func parseSessionTerminator(value string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out = append(out, value[i])
			continue
		}
		if i+1 >= len(value) {
			return nil, fmt.Errorf("invalid terminator escape: trailing backslash")
		}
		i++
		switch value[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(value) {
				return nil, fmt.Errorf("invalid terminator escape: \\x requires two hex digits")
			}
			b, err := strconv.ParseUint(value[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid terminator escape: \\x%s", value[i+1:i+3])
			}
			out = append(out, byte(b))
			i += 2
		default:
			return nil, fmt.Errorf("invalid terminator escape: \\%c", value[i])
		}
	}
	return out, nil
}
