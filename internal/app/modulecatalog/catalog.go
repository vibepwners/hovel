package modulecatalog

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ModuleType string

const (
	TypeSurvey          ModuleType = "survey"
	TypeExploit         ModuleType = "exploit"
	TypePayloadProvider ModuleType = "payload_provider"
)

type ValueType string

const (
	ValueString          ValueType = "string"
	ValueSecret          ValueType = "secret"
	ValueBool            ValueType = "bool"
	ValueInt             ValueType = "int"
	ValueFloat           ValueType = "float"
	ValueEnum            ValueType = "enum"
	ValueDuration        ValueType = "duration"
	ValueURL             ValueType = "url"
	ValueHost            ValueType = "host"
	ValuePort            ValueType = "port"
	ValueCIDR            ValueType = "cidr"
	ValuePath            ValueType = "path"
	ValueStringList      ValueType = "list<string>"
	ValueStringStringMap ValueType = "map<string,string>"
)

type Scope string

const (
	ScopeChain  Scope = "chain"
	ScopeTarget Scope = "target"
)

type Requirement struct {
	Key         string
	Type        ValueType
	Required    bool
	Default     string
	Description string
	Allowed     []string
	Secret      bool
}

type Module struct {
	ID           string
	Name         string
	Type         ModuleType
	Version      string
	Summary      string
	Description  string
	Tags         []string
	RuntimeKind  string
	Author       string
	Enabled      bool
	ChainConfig  []Requirement
	TargetConfig []Requirement
}

type Catalog struct {
	modules map[string]Module
}

func New(modules ...Module) Catalog {
	catalog := Catalog{modules: make(map[string]Module, len(modules))}
	for _, module := range modules {
		module.ID = strings.TrimSpace(module.ID)
		if module.ID == "" {
			continue
		}
		module.Tags = append([]string(nil), module.Tags...)
		module.ChainConfig = cloneRequirements(module.ChainConfig)
		module.TargetConfig = cloneRequirements(module.TargetConfig)
		catalog.modules[module.ID] = module
	}
	return catalog
}

func BuiltIns() Catalog {
	return New(
		Module{
			ID:          "mock-target-survey",
			Name:        "Mock Target Survey",
			Type:        TypeSurvey,
			Version:     "v0.0.0-mock",
			Summary:     "Collect mocked target facts.",
			Description: "Exercises per-target host and port configuration, fact output, and survey logs.",
			Tags:        []string{"mock", "survey", "target"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			TargetConfig: []Requirement{
				required("target.host", ValueHost, "Target host name or IP address."),
				required("target.port", ValuePort, "Target TCP port."),
			},
		},
		Module{
			ID:          "mock-auth-survey",
			Name:        "Mock Auth Survey",
			Type:        TypeSurvey,
			Version:     "v0.0.0-mock",
			Summary:     "Validate mocked authentication inputs.",
			Description: "Exercises string and secret target configuration with redacted display.",
			Tags:        []string{"mock", "survey", "auth"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			TargetConfig: []Requirement{
				required("auth.username", ValueString, "Username for mocked authentication."),
				secret("auth.password", "Password or token for mocked authentication."),
			},
		},
		Module{
			ID:          "mock-payload-provider",
			Name:        "Mock Payload Provider",
			Type:        TypePayloadProvider,
			Version:     "v0.0.0-mock",
			Summary:     "Select mocked payload metadata.",
			Description: "Exercises chain-level payload selection and target architecture requirements.",
			Tags:        []string{"mock", "payload"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []Requirement{
				enum("payload.kind", "Payload kind.", "command", "script", "shellcode"),
				enum("payload.os", "Payload operating system.", "linux", "windows", "darwin"),
			},
			TargetConfig: []Requirement{
				enum("target.arch", "Target architecture.", "x86_64", "arm64"),
			},
		},
		Module{
			ID:          "mock-simple-exploit",
			Name:        "Mock Simple Exploit",
			Type:        TypeExploit,
			Version:     "v0.0.0-mock",
			Summary:     "Run a mocked exploit flow.",
			Description: "Exercises throw transcript, findings, artifacts, and result rendering without target interaction.",
			Tags:        []string{"mock", "exploit"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []Requirement{
				required("operator.confirmed_lab", ValueBool, "Operator confirmed this is an authorized lab."),
			},
			TargetConfig: []Requirement{
				required("target.host", ValueHost, "Target host name or IP address."),
				required("target.port", ValuePort, "Target TCP port."),
			},
		},
		Module{
			ID:          "mock-config-kitchen-sink",
			Name:        "Mock Config Kitchen Sink",
			Type:        TypeSurvey,
			Version:     "v0.0.0-mock",
			Summary:     "Require every built-in config type.",
			Description: "Exercises all chain configuration parsers and display paths.",
			Tags:        []string{"mock", "config", "validation"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []Requirement{
				required("kitchen.string", ValueString, "String value."),
				secret("kitchen.secret", "Secret value."),
				required("kitchen.bool", ValueBool, "Boolean value."),
				required("kitchen.int", ValueInt, "Integer value."),
				required("kitchen.float", ValueFloat, "Float value."),
				enum("kitchen.enum", "Enum value.", "alpha", "beta"),
				required("kitchen.duration", ValueDuration, "Duration value."),
				required("kitchen.url", ValueURL, "URL value."),
				required("kitchen.host", ValueHost, "Host value."),
				required("kitchen.port", ValuePort, "Port value."),
				required("kitchen.cidr", ValueCIDR, "CIDR value."),
				required("kitchen.path", ValuePath, "Path value."),
				required("kitchen.list", ValueStringList, "Comma-separated list of strings."),
				required("kitchen.map", ValueStringStringMap, "Comma-separated key=value pairs."),
			},
		},
		Module{
			ID:          "mock-slow-step",
			Name:        "Mock Slow Step",
			Type:        TypeSurvey,
			Version:     "v0.0.0-mock",
			Summary:     "Emit delayed mocked progress.",
			Description: "Exercises live chain log fanout across connected entities.",
			Tags:        []string{"mock", "progress"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []Requirement{
				required("delay", ValueDuration, "Mock progress delay."),
			},
		},
		Module{
			ID:          "mock-failing-step",
			Name:        "Mock Failing Step",
			Type:        TypeExploit,
			Version:     "v0.0.0-mock",
			Summary:     "Fail at a selected mocked phase.",
			Description: "Exercises validation, planning, and execution error rendering.",
			Tags:        []string{"mock", "failure"},
			RuntimeKind: "native-builtin",
			Author:      "hovel",
			Enabled:     true,
			ChainConfig: []Requirement{
				enum("failure_mode", "Mock failure phase.", "validation", "planning", "execution"),
			},
		},
	)
}

func (c Catalog) List() []Module {
	modules := make([]Module, 0, len(c.modules))
	for _, module := range c.modules {
		modules = append(modules, cloneModule(module))
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].ID < modules[j].ID
	})
	return modules
}

func (c Catalog) ByType(moduleType ModuleType) []Module {
	var modules []Module
	for _, module := range c.List() {
		if module.Type == moduleType {
			modules = append(modules, module)
		}
	}
	return modules
}

func (c Catalog) Search(query string) []Module {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return c.List()
	}
	var modules []Module
	for _, module := range c.List() {
		haystack := strings.ToLower(module.ID + " " + module.Name + " " + module.Summary + " " + strings.Join(module.Tags, " "))
		if strings.Contains(haystack, query) {
			modules = append(modules, module)
		}
	}
	return modules
}

func (c Catalog) Find(id string) (Module, bool) {
	module, ok := c.modules[strings.TrimSpace(id)]
	if !ok {
		return Module{}, false
	}
	return cloneModule(module), true
}

func ValidateValue(requirement Requirement, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("value is required")
	}
	switch requirement.Type {
	case ValueString, ValueSecret, ValuePath:
		return nil
	case ValueBool:
		_, err := strconv.ParseBool(raw)
		return err
	case ValueInt:
		_, err := strconv.Atoi(raw)
		return err
	case ValueFloat:
		_, err := strconv.ParseFloat(raw, 64)
		return err
	case ValueEnum:
		for _, allowed := range requirement.Allowed {
			if raw == allowed {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(requirement.Allowed, ", "))
	case ValueDuration:
		_, err := time.ParseDuration(raw)
		return err
	case ValueURL:
		parsed, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return errors.New("must include scheme and host")
		}
		return nil
	case ValueHost:
		return validateHost(raw)
	case ValuePort:
		port, err := strconv.Atoi(raw)
		if err != nil {
			return err
		}
		if port < 1 || port > 65535 {
			return errors.New("must be between 1 and 65535")
		}
		return nil
	case ValueCIDR:
		_, _, err := net.ParseCIDR(raw)
		return err
	case ValueStringList:
		for _, item := range strings.Split(raw, ",") {
			if strings.TrimSpace(item) == "" {
				return errors.New("list items must not be empty")
			}
		}
		return nil
	case ValueStringStringMap:
		for _, item := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(item, "=")
			if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				return errors.New("map items must use key=value")
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown value type %q", requirement.Type)
	}
}

func DisplayValue(requirement Requirement, raw string) string {
	if requirement.Secret || requirement.Type == ValueSecret {
		if strings.TrimSpace(raw) == "" {
			return "<secret:missing>"
		}
		return "<secret:set>"
	}
	return raw
}

func required(key string, valueType ValueType, description string) Requirement {
	return Requirement{Key: key, Type: valueType, Required: true, Description: description}
}

func secret(key, description string) Requirement {
	return Requirement{Key: key, Type: ValueSecret, Required: true, Description: description, Secret: true}
}

func enum(key, description string, allowed ...string) Requirement {
	return Requirement{Key: key, Type: ValueEnum, Required: true, Description: description, Allowed: append([]string(nil), allowed...)}
}

func validateHost(raw string) error {
	if net.ParseIP(raw) != nil {
		return nil
	}
	if len(raw) > 253 {
		return errors.New("host is too long")
	}
	for _, label := range strings.Split(raw, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid host label")
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return errors.New("host contains invalid characters")
		}
	}
	return nil
}

func cloneModule(module Module) Module {
	module.Tags = append([]string(nil), module.Tags...)
	module.ChainConfig = cloneRequirements(module.ChainConfig)
	module.TargetConfig = cloneRequirements(module.TargetConfig)
	return module
}

func cloneRequirements(requirements []Requirement) []Requirement {
	out := make([]Requirement, 0, len(requirements))
	for _, requirement := range requirements {
		requirement.Allowed = append([]string(nil), requirement.Allowed...)
		out = append(out, requirement)
	}
	return out
}
