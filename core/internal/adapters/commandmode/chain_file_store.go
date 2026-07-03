package commandmode

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/adapters/descriptor"
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
	return descriptor.ParseChainFile(data)
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
		if strings.TrimSpace(step.Step) != "" {
			writeKV(&b, 6, "step", step.Step)
		}
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
