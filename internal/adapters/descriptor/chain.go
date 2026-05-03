package descriptor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
)

var chainStepUsesPattern = regexp.MustCompile(`^(module|service|provider):[^\s]+$`)

// CanonicalDescriptor is a schema-shaped descriptor normalized from JSON or YAML.
type CanonicalDescriptor struct {
	Kind string
	JSON []byte
}

// Decode parses a descriptor document from JSON or the alpha YAML subset used
// by persisted Hovel files, then returns canonical JSON bytes.
func Decode(data []byte) (CanonicalDescriptor, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		parsed, yamlErr := parseYAMLDescriptor(string(data))
		if yamlErr != nil {
			return CanonicalDescriptor{}, err
		}
		value = parsed
	}
	object, ok := value.(map[string]any)
	if !ok {
		return CanonicalDescriptor{}, errors.New("descriptor must be an object")
	}
	kind, _ := object["kind"].(string)
	if strings.TrimSpace(kind) == "" {
		return CanonicalDescriptor{}, errors.New("descriptor kind is required")
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return CanonicalDescriptor{}, err
	}
	return CanonicalDescriptor{Kind: kind, JSON: canonical}, nil
}

// ParseChainFile validates a Chain descriptor and returns the app command model.
func ParseChainFile(data []byte) (commands.ChainFile, error) {
	descriptor, err := Decode(data)
	if err != nil {
		return commands.ChainFile{}, err
	}
	if descriptor.Kind != "Chain" {
		return commands.ChainFile{}, fmt.Errorf("chain file schema: kind must be Chain")
	}
	if err := ValidateChainSchemaJSON(descriptor.JSON); err != nil {
		return commands.ChainFile{}, err
	}
	var file commands.ChainFile
	if err := json.Unmarshal(descriptor.JSON, &file); err != nil {
		return commands.ChainFile{}, err
	}
	return file, nil
}

// ValidateChainSchemaJSON enforces the product chain-file schema at runtime.
func ValidateChainSchemaJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := requireKeys("chain file schema", raw, []string{"apiVersion", "kind", "metadata", "spec"}); err != nil {
		return err
	}
	if err := rejectAdditional("chain file schema", raw, []string{"apiVersion", "kind", "metadata", "spec"}); err != nil {
		return err
	}
	if raw["apiVersion"] != expectedAPIVersion {
		return fmt.Errorf("chain file schema: apiVersion must be %s", expectedAPIVersion)
	}
	if raw["kind"] != "Chain" {
		return fmt.Errorf("chain file schema: kind must be Chain")
	}
	metadata, ok := raw["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("chain file schema: metadata must be an object")
	}
	if err := requireKeys("chain file schema metadata", metadata, []string{"name"}); err != nil {
		return err
	}
	if err := rejectAdditional("chain file schema metadata", metadata, []string{"name", "version", "description", "tags"}); err != nil {
		return err
	}
	if err := requireString("chain file schema metadata.name", metadata["name"]); err != nil {
		return err
	}
	spec, ok := raw["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("chain file schema: spec must be an object")
	}
	if err := requireKeys("chain file schema spec", spec, []string{"mode", "steps"}); err != nil {
		return err
	}
	if err := rejectAdditional("chain file schema spec", spec, []string{"mode", "steps", "config", "targets", "targetConfigs"}); err != nil {
		return err
	}
	mode, ok := spec["mode"].(string)
	if !ok || (mode != "template" && mode != "configured") {
		return fmt.Errorf("chain file schema spec.mode must be template or configured")
	}
	if err := validateSteps(spec["steps"]); err != nil {
		return err
	}
	if value, ok := spec["config"]; ok {
		if err := validateStringMap("chain file schema spec.config", value); err != nil {
			return err
		}
	}
	if value, ok := spec["targets"]; ok {
		if err := validateTargets(value); err != nil {
			return err
		}
	}
	if value, ok := spec["targetConfigs"]; ok {
		if err := validateTargetConfigs(value); err != nil {
			return err
		}
	}
	return nil
}

func validateSteps(value any) error {
	steps, ok := value.([]any)
	if !ok {
		return fmt.Errorf("chain file schema spec.steps must be an array")
	}
	if len(steps) == 0 {
		return fmt.Errorf("chain file schema spec.steps must contain at least one step")
	}
	for index, item := range steps {
		step, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("chain file schema spec.steps[%d] must be an object", index)
		}
		if err := requireKeys(fmt.Sprintf("chain file schema spec.steps[%d]", index), step, []string{"id", "uses"}); err != nil {
			return err
		}
		if err := rejectAdditional(fmt.Sprintf("chain file schema spec.steps[%d]", index), step, []string{"id", "uses"}); err != nil {
			return err
		}
		if err := requireString(fmt.Sprintf("chain file schema spec.steps[%d].id", index), step["id"]); err != nil {
			return err
		}
		uses, ok := step["uses"].(string)
		if !ok || !chainStepUsesPattern.MatchString(uses) {
			return fmt.Errorf("chain file schema spec.steps[%d].uses must match module:, service:, or provider: reference", index)
		}
	}
	return nil
}

func validateTargets(value any) error {
	targets, ok := value.([]any)
	if !ok {
		return fmt.Errorf("chain file schema spec.targets must be an array")
	}
	for index, item := range targets {
		target, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("chain file schema spec.targets[%d] must be an object", index)
		}
		if err := requireKeys(fmt.Sprintf("chain file schema spec.targets[%d]", index), target, []string{"id"}); err != nil {
			return err
		}
		if err := rejectAdditional(fmt.Sprintf("chain file schema spec.targets[%d]", index), target, []string{"id", "config"}); err != nil {
			return err
		}
		if err := requireString(fmt.Sprintf("chain file schema spec.targets[%d].id", index), target["id"]); err != nil {
			return err
		}
		if value, ok := target["config"]; ok {
			if err := validateStringMap(fmt.Sprintf("chain file schema spec.targets[%d].config", index), value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTargetConfigs(value any) error {
	configs, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("chain file schema spec.targetConfigs must be an object")
	}
	for target, config := range configs {
		if err := validateStringMap("chain file schema spec.targetConfigs."+target, config); err != nil {
			return err
		}
	}
	return nil
}

func validateStringMap(path string, value any) error {
	values, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", path)
	}
	for key, item := range values {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("%s.%s must be a string", path, key)
		}
	}
	return nil
}

func requireKeys(path string, values map[string]any, keys []string) error {
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return fmt.Errorf("%s missing required key %s", path, key)
		}
	}
	return nil
}

func rejectAdditional(path string, values map[string]any, allowed []string) error {
	seen := map[string]bool{}
	for _, key := range allowed {
		seen[key] = true
	}
	for key := range values {
		if !seen[key] {
			return fmt.Errorf("%s unexpected key %s", path, key)
		}
	}
	return nil
}

func requireString(path string, value any) error {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return fmt.Errorf("%s must be a non-empty string", path)
	}
	return nil
}

func parseYAMLDescriptor(text string) (map[string]any, error) {
	file, err := parseChainYAML(text)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseChainYAML(text string) (commands.ChainFile, error) {
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
