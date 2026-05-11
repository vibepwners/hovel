package descriptor

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"gopkg.in/yaml.v3"
)

var chainStepUsesPattern = regexp.MustCompile(`^(module|service|provider):[^\s]+$`)

// CanonicalDescriptor is a schema-shaped descriptor normalized from JSON or YAML.
type CanonicalDescriptor struct {
	Kind string
	JSON []byte
}

// Decode parses a descriptor document from JSON or YAML, then returns canonical
// JSON bytes for schema validation.
func Decode(data []byte) (CanonicalDescriptor, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		parsed, yamlErr := parseYAMLDescriptor(data)
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

func parseYAMLDescriptor(data []byte) (map[string]any, error) {
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	converted, err := yamlToJSONValue(value)
	if err != nil {
		return nil, err
	}
	object, ok := converted.(map[string]any)
	if !ok {
		return nil, errors.New("descriptor must be an object")
	}
	return object, nil
}

func yamlToJSONValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			converted, err := yamlToJSONValue(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			keyText, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("descriptor YAML map key %v must be a string", key)
			}
			converted, err := yamlToJSONValue(item)
			if err != nil {
				return nil, err
			}
			out[keyText] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			converted, err := yamlToJSONValue(item)
			if err != nil {
				return nil, err
			}
			out[index] = converted
		}
		return out, nil
	default:
		return typed, nil
	}
}
