package commandmode

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
)

type chainFileDiskStore struct{}

func (chainFileDiskStore) WriteChainFile(ctx context.Context, path string, file commands.ChainFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("chain file path is required")
	}
	return os.WriteFile(path, []byte(formatChainFile(file)), 0o644)
}

func (chainFileDiskStore) ReadChainFile(ctx context.Context, path string) (commands.ChainFile, error) {
	if err := ctx.Err(); err != nil {
		return commands.ChainFile{}, err
	}
	if strings.TrimSpace(path) == "" {
		return commands.ChainFile{}, fmt.Errorf("chain file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return commands.ChainFile{}, err
	}
	return parseChainFile(string(data))
}

func formatChainFile(file commands.ChainFile) string {
	var b strings.Builder
	writeKV(&b, 0, "apiVersion", file.APIVersion)
	writeKV(&b, 0, "kind", file.Kind)
	b.WriteString("metadata:\n")
	writeKV(&b, 2, "name", file.Metadata.Name)
	b.WriteString("spec:\n")
	writeKV(&b, 2, "mode", file.Spec.Mode)
	b.WriteString("  steps:\n")
	for _, step := range file.Spec.Steps {
		writeListKV(&b, 4, "id", step.ID)
		writeKV(&b, 6, "uses", step.Uses)
	}
	if file.Spec.Mode != "template" {
		writeMap(&b, 2, "config", file.Spec.Config)
		b.WriteString("  targets:\n")
		for _, target := range file.Spec.Targets {
			writeListKV(&b, 4, "id", target.ID)
			writeMap(&b, 6, "config", target.Config)
		}
	}
	return b.String()
}

func writeKV(b *strings.Builder, indent int, key, value string) {
	b.WriteString(strings.Repeat(" ", indent))
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(strconv.Quote(value))
	b.WriteString("\n")
}

func writeListKV(b *strings.Builder, indent int, key, value string) {
	b.WriteString(strings.Repeat(" ", indent))
	b.WriteString("- ")
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(strconv.Quote(value))
	b.WriteString("\n")
}

func writeMap(b *strings.Builder, indent int, key string, values map[string]string) {
	if len(values) == 0 {
		return
	}
	b.WriteString(strings.Repeat(" ", indent))
	b.WriteString(key)
	b.WriteString(":\n")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, item := range keys {
		writeKV(b, indent+2, strconv.Quote(item), values[item])
	}
}

func parseChainFile(text string) (commands.ChainFile, error) {
	file := commands.ChainFile{}
	var section string
	var currentTarget *commands.ChainFileTarget
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := leadingSpaces(raw)
		line := strings.TrimSpace(raw)
		switch {
		case indent == 0 && strings.HasPrefix(line, "apiVersion:"):
			file.APIVersion = yamlValue(line)
		case indent == 0 && strings.HasPrefix(line, "kind:"):
			file.Kind = yamlValue(line)
		case indent == 0 && line == "metadata:":
			section = "metadata"
		case indent == 0 && line == "spec:":
			section = "spec"
		case indent == 2 && section == "metadata" && strings.HasPrefix(line, "name:"):
			file.Metadata.Name = yamlValue(line)
		case indent == 2 && strings.HasPrefix(line, "mode:"):
			file.Spec.Mode = yamlValue(line)
			section = "spec"
		case indent == 2 && line == "steps:":
			section = "steps"
		case indent == 4 && section == "steps" && strings.HasPrefix(line, "- id:"):
			file.Spec.Steps = append(file.Spec.Steps, commands.ChainFileStep{ID: yamlValue(strings.TrimPrefix(line, "- "))})
		case indent == 6 && section == "steps" && strings.HasPrefix(line, "uses:"):
			if len(file.Spec.Steps) == 0 {
				return commands.ChainFile{}, fmt.Errorf("chain file step uses without step id")
			}
			file.Spec.Steps[len(file.Spec.Steps)-1].Uses = yamlValue(line)
		case indent == 2 && line == "config:":
			section = "config"
			file.Spec.Config = map[string]string{}
		case indent == 4 && section == "config":
			key, value, ok := yamlPair(line)
			if ok {
				file.Spec.Config[key] = value
			}
		case indent == 2 && line == "targets:":
			section = "targets"
		case indent == 4 && section == "targets" && strings.HasPrefix(line, "- id:"):
			file.Spec.Targets = append(file.Spec.Targets, commands.ChainFileTarget{ID: yamlValue(strings.TrimPrefix(line, "- "))})
			currentTarget = &file.Spec.Targets[len(file.Spec.Targets)-1]
		case indent == 6 && section == "targets" && line == "config:":
			if currentTarget == nil {
				return commands.ChainFile{}, fmt.Errorf("chain file target config without target")
			}
			currentTarget.Config = map[string]string{}
			section = "target-config"
		case indent == 8 && section == "target-config":
			key, value, ok := yamlPair(line)
			if ok && currentTarget != nil {
				currentTarget.Config[key] = value
			}
		case indent == 4 && section == "target-config" && strings.HasPrefix(line, "- id:"):
			section = "targets"
			file.Spec.Targets = append(file.Spec.Targets, commands.ChainFileTarget{ID: yamlValue(strings.TrimPrefix(line, "- "))})
			currentTarget = &file.Spec.Targets[len(file.Spec.Targets)-1]
		}
	}
	if err := scanner.Err(); err != nil {
		return commands.ChainFile{}, err
	}
	if file.Spec.Mode == "" {
		file.Spec.Mode = "configured"
	}
	return file, nil
}

func leadingSpaces(text string) int {
	return len(text) - len(strings.TrimLeft(text, " "))
}

func yamlValue(line string) string {
	_, value, ok := strings.Cut(line, ":")
	if !ok {
		return ""
	}
	return unquoteYAML(strings.TrimSpace(value))
}

func yamlPair(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return unquoteYAML(strings.TrimSpace(key)), unquoteYAML(strings.TrimSpace(value)), true
}

func unquoteYAML(value string) string {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}
