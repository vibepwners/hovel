package modulecatalog

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
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
	ID            string
	Name          string
	Type          ModuleType
	Version       string
	Summary       string
	Description   string
	Tags          []string
	RuntimeKind   string
	Author        string
	Enabled       bool
	ChainConfig   []Requirement
	TargetConfig  []Requirement
	StepContracts StepContractSet
}

type CapabilityType string

const (
	CapabilityRemoteExecution CapabilityType = "RemoteExecutionCapability"
	CapabilityCredential      CapabilityType = "CredentialCapability"
	CapabilityPayloadArtifact CapabilityType = "PayloadArtifact"
	CapabilityPayloadInstance CapabilityType = "PayloadInstance"
	CapabilityTransport       CapabilityType = "TransportEndpoint"
	CapabilitySessionRef      CapabilityType = "SessionRef"
	CapabilityCleanupHandle   CapabilityType = "CleanupHandle"
)

type StepContractSet struct {
	Version string
	Steps   []StepContract
}

type StepContract struct {
	ID           string
	Kind         string
	ConfigSchema map[string]any
	Requires     []CapabilityRequirement
	Produces     []CapabilityRequirement
	Prepare      StepPrepareContract
	Cleanup      *StepCleanupContract
}

type CapabilityRequirement struct {
	Type          CapabilityType
	SchemaVersion string
	Attributes    map[string]any
	States        []string
}

type Capability struct {
	ID             string
	Type           CapabilityType
	SchemaVersion  string
	State          string
	ProducerStepID string
	Attributes     map[string]any
	Extensions     map[string]any
}

type CapabilityRef struct {
	CapabilityID string
	Type         CapabilityType
}

type StepInputResolution struct {
	StepID   string
	Ready    bool
	Bindings []CapabilityBinding
	Missing  []MissingCapability
}

type CapabilityBinding struct {
	RequirementIndex int
	CapabilityID     string
}

type MissingCapability struct {
	RequirementIndex int
	Type             CapabilityType
	SchemaVersion    string
	Attributes       map[string]any
	States           []string
}

type StepAvailability struct {
	ModuleID   string
	Step       StepContract
	Resolution StepInputResolution
}

type StepPrepareContract struct {
	Materializes []string
}

type StepCleanupContract struct {
	StepID string
}

type StepContractIssue struct {
	ModuleID string
	StepID   string
	Message  string
}

// DangerTag marks a module that may perform destructive or otherwise dangerous
// actions. Modules advertise it through their descriptor tags; the operator must
// explicitly opt in before such a module can be thrown.
const DangerTag = "dangerous"

// Dangerous reports whether the module is tagged as dangerous (case-insensitive).
func (m Module) Dangerous() bool {
	for _, tag := range m.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), DangerTag) {
			return true
		}
	}
	return false
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

func (c Catalog) ResolveStepAvailability(capabilities []Capability) []StepAvailability {
	var availability []StepAvailability
	for _, module := range c.List() {
		if !module.Enabled {
			continue
		}
		for _, step := range module.StepContracts.Steps {
			availability = append(availability, StepAvailability{
				ModuleID:   module.ID,
				Step:       cloneStepContract(step),
				Resolution: ResolveStepInputs(step, capabilities),
			})
		}
	}
	sort.Slice(availability, func(i, j int) bool {
		if availability[i].ModuleID != availability[j].ModuleID {
			return availability[i].ModuleID < availability[j].ModuleID
		}
		return availability[i].Step.ID < availability[j].Step.ID
	})
	return availability
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
	module.StepContracts = cloneStepContractSet(module.StepContracts)
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
	if requirement.Secret || requirement.Type == ValueSecret {
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		return "********"
	}
	return raw
}

func ValidateStepContracts(module Module) []StepContractIssue {
	var issues []StepContractIssue
	for _, step := range module.StepContracts.Steps {
		stepID := strings.TrimSpace(step.ID)
		if stepID == "" {
			issues = append(issues, StepContractIssue{
				ModuleID: module.ID,
				Message:  "step id is required",
			})
		}
		if strings.TrimSpace(step.Kind) == "" {
			issues = append(issues, StepContractIssue{
				ModuleID: module.ID,
				StepID:   stepID,
				Message:  "step kind is required",
			})
		}
		issues = append(issues, validateCapabilityRequirements(module.ID, stepID, "requirement", step.Requires)...)
		issues = append(issues, validateCapabilityRequirements(module.ID, stepID, "produced capability", step.Produces)...)
	}
	return issues
}

func validateCapabilityRequirements(moduleID, stepID, label string, requirements []CapabilityRequirement) []StepContractIssue {
	var issues []StepContractIssue
	for index, requirement := range requirements {
		position := index + 1
		if strings.TrimSpace(string(requirement.Type)) == "" {
			issues = append(issues, StepContractIssue{
				ModuleID: moduleID,
				StepID:   stepID,
				Message:  fmt.Sprintf("%s %d type is required", label, position),
			})
		}
		if strings.TrimSpace(requirement.SchemaVersion) == "" {
			issues = append(issues, StepContractIssue{
				ModuleID: moduleID,
				StepID:   stepID,
				Message:  fmt.Sprintf("%s %d schemaVersion is required", label, position),
			})
		}
	}
	return issues
}

func CapabilitySatisfiesRequirement(capability Capability, requirement CapabilityRequirement) bool {
	if requirement.Type != "" && capability.Type != requirement.Type {
		return false
	}
	if requirement.SchemaVersion != "" && capability.SchemaVersion != requirement.SchemaVersion {
		return false
	}
	if len(requirement.States) > 0 && !containsString(requirement.States, capability.State) {
		return false
	}
	for key, want := range requirement.Attributes {
		got, ok := capability.Attributes[key]
		if !ok || !reflect.DeepEqual(got, want) {
			return false
		}
	}
	return true
}

func FindSatisfyingCapability(requirement CapabilityRequirement, capabilities []Capability) (Capability, bool) {
	for _, capability := range capabilities {
		if CapabilitySatisfiesRequirement(capability, requirement) {
			return capability, true
		}
	}
	return Capability{}, false
}

func ResolveStepInputs(step StepContract, capabilities []Capability) StepInputResolution {
	resolution := StepInputResolution{
		StepID:   step.ID,
		Ready:    true,
		Bindings: make([]CapabilityBinding, 0, len(step.Requires)),
	}
	for index, requirement := range step.Requires {
		capability, ok := FindSatisfyingCapability(requirement, capabilities)
		if ok {
			resolution.Bindings = append(resolution.Bindings, CapabilityBinding{
				RequirementIndex: index,
				CapabilityID:     capability.ID,
			})
			continue
		}
		resolution.Ready = false
		resolution.Missing = append(resolution.Missing, MissingCapability{
			RequirementIndex: index,
			Type:             requirement.Type,
			SchemaVersion:    requirement.SchemaVersion,
			Attributes:       cloneAnyMap(requirement.Attributes),
			States:           append([]string(nil), requirement.States...),
		})
	}
	return resolution
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
	module.StepContracts = cloneStepContractSet(module.StepContracts)
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

func cloneStepContractSet(set StepContractSet) StepContractSet {
	set.Steps = cloneStepContracts(set.Steps)
	return set
}

func cloneStepContracts(steps []StepContract) []StepContract {
	out := make([]StepContract, 0, len(steps))
	for _, step := range steps {
		out = append(out, cloneStepContract(step))
	}
	return out
}

func cloneStepContract(step StepContract) StepContract {
	step.ConfigSchema = cloneAnyMap(step.ConfigSchema)
	step.Requires = cloneCapabilityRequirements(step.Requires)
	step.Produces = cloneCapabilityRequirements(step.Produces)
	step.Prepare.Materializes = append([]string(nil), step.Prepare.Materializes...)
	if step.Cleanup != nil {
		cleanup := *step.Cleanup
		step.Cleanup = &cleanup
	}
	return step
}

func cloneCapabilityRequirements(requirements []CapabilityRequirement) []CapabilityRequirement {
	out := make([]CapabilityRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		requirement.Attributes = cloneAnyMap(requirement.Attributes)
		requirement.States = append([]string(nil), requirement.States...)
		out = append(out, requirement)
	}
	return out
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
