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

	domainmodule "github.com/Vibe-Pwners/hovel/internal/domain/module"
)

type ModuleType = domainmodule.Type

const (
	TypeSurvey          = domainmodule.TypeSurvey
	TypeExploit         = domainmodule.TypeExploit
	TypePayloadProvider = domainmodule.TypePayloadProvider
)

const (
	RuntimeJSONRPCStdio = "jsonrpc-stdio"
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
	aliases map[string]string
}

func New(modules ...Module) Catalog {
	catalog := Catalog{
		modules: make(map[string]Module, len(modules)),
		aliases: make(map[string]string, len(modules)),
	}
	for _, module := range modules {
		module = normalizeModule(module)
		if module.ID == "" {
			continue
		}
		catalog.modules[module.ID] = module
		catalog.trackLatestAlias(module)
	}
	return catalog
}

func BuiltIns() Catalog {
	return New()
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
		haystack := strings.ToLower(module.ID + " " + ReferenceName(module.ID) + " " + module.Name + " " + module.Summary + " " + strings.Join(module.Tags, " "))
		if strings.Contains(haystack, query) {
			modules = append(modules, module)
		}
	}
	return modules
}

func (c Catalog) Find(id string) (Module, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Module{}, false
	}
	module, ok := c.modules[id]
	if !ok {
		if canonicalID, hasAlias := c.aliases[id]; hasAlias {
			module, ok = c.modules[canonicalID]
		}
	}
	if !ok {
		return Module{}, false
	}
	return cloneModule(module), true
}

func NewModuleType(value string) (ModuleType, error) {
	return domainmodule.NewType(value)
}

func CanonicalID(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

func SplitID(id string) (name, version string, hasVersion bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", "", false
	}
	name, version, hasVersion = strings.Cut(id, "@")
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if !hasVersion || name == "" || version == "" {
		return id, "", false
	}
	return name, version, true
}

func ReferenceName(id string) string {
	name, _, _ := SplitID(id)
	return name
}

func normalizeModule(module Module) Module {
	module.ID = strings.TrimSpace(module.ID)
	module.Version = strings.TrimSpace(module.Version)
	name, version, hasVersion := SplitID(module.ID)
	switch {
	case module.ID == "":
		return module
	case hasVersion && module.Version == "":
		module.ID = CanonicalID(name, version)
		module.Version = version
	case hasVersion:
		module.ID = CanonicalID(name, module.Version)
	case module.Version != "":
		module.ID = CanonicalID(module.ID, module.Version)
	}
	module.Tags = append([]string(nil), module.Tags...)
	module.ChainConfig = cloneRequirements(module.ChainConfig)
	module.TargetConfig = cloneRequirements(module.TargetConfig)
	return module
}

func (c Catalog) trackLatestAlias(module Module) {
	name := ReferenceName(module.ID)
	if name == "" || name == module.ID {
		return
	}
	currentID, ok := c.aliases[name]
	if !ok {
		c.aliases[name] = module.ID
		return
	}
	current := c.modules[currentID]
	cmp := compareVersions(module.Version, current.Version)
	if cmp > 0 || cmp == 0 && module.ID > currentID {
		c.aliases[name] = module.ID
	}
}

func compareVersions(left, right string) int {
	left = normalizeVersion(left)
	right = normalizeVersion(right)
	leftCore, leftPre := splitVersion(left)
	rightCore, rightPre := splitVersion(right)
	maxLen := len(leftCore)
	if len(rightCore) > maxLen {
		maxLen = len(rightCore)
	}
	for i := 0; i < maxLen; i++ {
		var leftValue, rightValue int
		if i < len(leftCore) {
			leftValue = leftCore[i]
		}
		if i < len(rightCore) {
			rightValue = rightCore[i]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	switch {
	case leftPre == "" && rightPre != "":
		return 1
	case leftPre != "" && rightPre == "":
		return -1
	case leftPre < rightPre:
		return -1
	case leftPre > rightPre:
		return 1
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(strings.ToLower(version))
	return strings.TrimPrefix(version, "v")
}

func splitVersion(version string) ([]int, string) {
	core := version
	if before, _, ok := strings.Cut(core, "+"); ok {
		core = before
	}
	pre := ""
	if before, after, ok := strings.Cut(core, "-"); ok {
		core = before
		pre = after
	}
	parts := strings.Split(core, ".")
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			values = append(values, 0)
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			value = 0
		}
		values = append(values, value)
	}
	return values, pre
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
	return raw
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
