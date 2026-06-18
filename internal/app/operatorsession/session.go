package operatorsession

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

const DefaultOperation = "default"

type Operation struct {
	Name          string
	Targets       []string
	TargetConfigs map[string]map[string]string
	TargetSets    []TargetSet
	Chains        []Chain
}

type Chain struct {
	Name          string
	Targets       []string
	Steps         []Step
	Config        map[string]string
	TargetConfigs map[string]map[string]string
	LogTopic      string
	Logs          []operatorlog.Entry
	nextStep      int
}

type Step struct {
	ID       string
	ModuleID string
	StepID   string `json:"stepId,omitempty"`
}

type TargetSet struct {
	Name    string
	Targets []string
}

type State struct {
	ActiveOperation string
	Operation       string
	ActiveChain     string
	Chain           string
	Targets         []string
	Steps           []Step
	Config          map[string]string
	TargetConfigs   map[string]map[string]string
	TargetSets      []TargetSet
	LogTopic        string
	Chains          []Chain
	Operations      []Operation
}

type PersistedState struct {
	ActiveOperation string               `json:"activeOperation,omitempty"`
	ActiveChain     string               `json:"activeChain"`
	Operations      []PersistedOperation `json:"operations,omitempty"`
	Chains          []PersistedChain     `json:"chains,omitempty"`
}

type PersistedOperation struct {
	Name          string                       `json:"name"`
	Targets       []string                     `json:"targets,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	TargetSets    []TargetSet                  `json:"targetSets,omitempty"`
	Chains        []PersistedChain             `json:"chains"`
}

type PersistedChain struct {
	Name          string                       `json:"name"`
	Targets       []string                     `json:"targets"`
	Steps         []Step                       `json:"steps"`
	Config        map[string]string            `json:"config"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs"`
	LogTopic      string                       `json:"logTopic"`
	Logs          []operatorlog.Entry          `json:"logs"`
}

type Store struct {
	mu         sync.Mutex
	operations map[string]*operationState
}

type operationState struct {
	Name          string
	Targets       []string
	TargetConfigs map[string]map[string]string
	TargetSets    []TargetSet
	chains        map[string]*Chain
}

func New() *Session {
	return NewWithStore(NewStore())
}

func NewStore() *Store {
	return &Store{operations: map[string]*operationState{}}
}

type Session struct {
	mu                      sync.Mutex
	activeOperation         string
	activeOperationSelected bool
	activeChains            map[string]string
	store                   *Store
}

func NewWithStore(store *Store) *Session {
	if store == nil {
		store = NewStore()
	}
	return &Session{
		activeChains: map[string]string{},
		store:        store,
	}
}

func (s *Session) CreateOperation(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("operation is required")
	}
	return s.chainStore().createOperation(name)
}

func (s *Session) UseOperation(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("operation is required")
	}
	if err := s.chainStore().createOperation(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeOperation = name
	s.activeOperationSelected = true
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	return nil
}

func (s *Session) CreateChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	return s.chainStore().createChain(s.activeOperationName(), name)
}

func (s *Session) UseChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	operation := s.activeOperationName()
	if err := s.chainStore().createChain(operation, name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	s.activeChains[operation] = name
	return nil
}

func (s *Session) RenameChain(oldName, newName string) error {
	oldName = normalizeName(oldName)
	newName = normalizeName(newName)
	if oldName == "" || newName == "" {
		return errors.New("chain is required")
	}
	operation := s.activeOperationName()
	if err := s.chainStore().renameChain(operation, oldName, newName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains[operation] == oldName {
		s.activeChains[operation] = newName
	}
	return nil
}

func (s *Session) DeleteChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	operation := s.activeOperationName()
	if err := s.chainStore().deleteChain(operation, name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains[operation] == name {
		s.activeChains[operation] = ""
	}
	return nil
}

func (s *Session) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("target is required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().addTarget(operation, activeChain, target)
}

func (s *Session) ClearTargets() {
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return
	}
	s.chainStore().clearTargets(operation, activeChain)
}

func (s *Session) CreateTargetSet(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("target set is required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().createTargetSet(operation, activeChain, name)
}

func (s *Session) AddTargetToSet(name, target string) error {
	name = normalizeName(name)
	target = strings.TrimSpace(target)
	if name == "" || target == "" {
		return errors.New("target set and target are required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().addTargetToSet(operation, activeChain, name, target)
}

func (s *Session) RemoveTargetFromSet(name, target string) error {
	name = normalizeName(name)
	target = strings.TrimSpace(target)
	if name == "" || target == "" {
		return errors.New("target set and target are required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().removeTargetFromSet(operation, activeChain, name, target)
}

func (s *Session) AddModule(moduleID string) (Step, error) {
	return s.AddStep(moduleID, "")
}

func (s *Session) AddStep(moduleID, stepID string) (Step, error) {
	moduleID = strings.TrimSpace(moduleID)
	if moduleID == "" {
		return Step{}, errors.New("module is required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" {
		return Step{}, errors.New("active chain is required")
	}
	return s.chainStore().addModule(operation, activeChain, moduleID, stepID)
}

func (s *Session) SetChainConfig(key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return errors.New("config key and value are required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().setChainConfig(operation, activeChain, key, value)
}

func (s *Session) UnsetChainConfig(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("config key is required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().unsetChainConfig(operation, activeChain, key)
}

func (s *Session) SetTargetConfig(target, key, value string) error {
	target = strings.TrimSpace(target)
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if target == "" || key == "" || value == "" {
		return errors.New("target, config key, and value are required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().setTargetConfig(operation, activeChain, target, key, value)
}

func (s *Session) UnsetTargetConfig(target, key string) error {
	target = strings.TrimSpace(target)
	key = strings.TrimSpace(key)
	if target == "" || key == "" {
		return errors.New("target and config key are required")
	}
	operation, activeChain := s.activeRef()
	if activeChain == "" && !s.ActiveOperationSelected() {
		return errors.New("active operation is required")
	}
	return s.chainStore().unsetTargetConfig(operation, activeChain, target, key)
}

func (s *Session) AppendLog(entries ...operatorlog.Entry) error {
	_, activeChain := s.activeRef()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.AppendLogToChain(activeChain, entries...)
}

func (s *Session) AppendLogToChain(name string, entries ...operatorlog.Entry) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	return s.chainStore().appendLog(s.activeOperationName(), name, entries...)
}

func (s *Session) Snapshot() State {
	operation, activeChain := s.activeRef()
	return s.chainStore().snapshot(operation, activeChain)
}

func (s *Session) ActiveOperationSelected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return normalizeOperation(s.activeOperation) != "" && s.activeOperationSelected
}

func (s *Session) ActiveLogs() []operatorlog.Entry {
	operation, activeChain := s.activeRef()
	return s.chainStore().logs(operation, activeChain)
}

func (s *Session) Export() PersistedState {
	operation, activeChain := s.activeRef()
	state := s.chainStore().export(operation, activeChain)
	if !s.ActiveOperationSelected() {
		state.ActiveOperation = ""
	}
	return state
}

func (s *Session) Import(state PersistedState) {
	s.chainStore().importState(state)
	activeOperation := normalizeOperation(state.ActiveOperation)
	activeOperationSelected := activeOperation != ""
	if activeOperation == "" {
		activeOperation = DefaultOperation
	}
	activeChain := normalizeName(state.ActiveChain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	if s.store.hasOperation(activeOperation) {
		s.activeOperation = activeOperation
		s.activeOperationSelected = activeOperationSelected
		if activeChain != "" && s.store.hasChain(activeOperation, activeChain) {
			s.activeChains[activeOperation] = activeChain
			return
		}
		s.activeChains[activeOperation] = ""
		return
	}
	s.activeOperation = DefaultOperation
	s.activeOperationSelected = false
	s.activeChains[DefaultOperation] = ""
}

func (s *Session) Attachment(operation, chain string) *Session {
	attachment := NewWithStore(s.chainStore())
	if normalizeOperation(operation) != "" {
		_ = attachment.UseOperation(operation)
	}
	if normalizeName(chain) != "" {
		_ = attachment.UseChain(chain)
	}
	return attachment
}

func (s *Session) activeOperationName() string {
	operation, _ := s.activeRef()
	return operation
}

func (s *Session) activeRef() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := normalizeOperation(s.activeOperation)
	if operation == "" {
		operation = DefaultOperation
	}
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	return operation, s.activeChains[operation]
}

func (s *Session) chainStore() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = NewStore()
	}
	return s.store
}

func (s *Store) createOperation(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureOperation(name)
	return nil
}

func (s *Store) createChain(operationName, chainName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureChain(operationName, chainName)
	return nil
}

func (s *Store) renameChain(operationName, oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	chain, ok := operation.chains[oldName]
	if !ok {
		return errors.New("chain does not exist")
	}
	if oldName == newName {
		return nil
	}
	if _, exists := operation.chains[newName]; exists {
		return errors.New("chain already exists")
	}
	delete(operation.chains, oldName)
	chain.Name = newName
	chain.LogTopic = logTopic(operation.Name, newName)
	operation.chains[newName] = chain
	return nil
}

func (s *Store) deleteChain(operationName, chainName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if _, ok := operation.chains[chainName]; !ok {
		return errors.New("chain does not exist")
	}
	delete(operation.chains, chainName)
	return nil
}

func (s *Store) addTarget(operationName, chainName, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if !hasString(operation.Targets, target) {
		if operation.TargetConfigs == nil {
			operation.TargetConfigs = map[string]map[string]string{}
		}
		operation.TargetConfigs[target] = map[string]string{}
		operation.Targets = append(operation.Targets, target)
	}
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("target", "target added",
			operatorlog.Field{Name: "target", Value: target},
		))
	}
	return nil
}

func (s *Store) clearTargets(operationName, chainName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	operation.Targets = nil
	operation.TargetConfigs = map[string]map[string]string{}
	operation.TargetSets = nil
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("target", "targets cleared"))
	}
}

func (s *Store) createTargetSet(operationName, chainName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if findTargetSet(operation.TargetSets, name) >= 0 {
		return nil
	}
	operation.TargetSets = append(operation.TargetSets, TargetSet{Name: name})
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("target", "target set created",
			operatorlog.Field{Name: "targetSet", Value: name},
		))
	}
	return nil
}

func (s *Store) addTargetToSet(operationName, chainName, name, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if !hasString(operation.Targets, target) {
		return errors.New("target does not exist")
	}
	index := findTargetSet(operation.TargetSets, name)
	if index < 0 {
		operation.TargetSets = append(operation.TargetSets, TargetSet{Name: name})
		index = len(operation.TargetSets) - 1
	}
	if !hasString(operation.TargetSets[index].Targets, target) {
		operation.TargetSets[index].Targets = append(operation.TargetSets[index].Targets, target)
	}
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("target", "target added to set",
			operatorlog.Field{Name: "targetSet", Value: name},
			operatorlog.Field{Name: "target", Value: target},
		))
	}
	return nil
}

func (s *Store) removeTargetFromSet(operationName, chainName, name, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	index := findTargetSet(operation.TargetSets, name)
	if index < 0 {
		return errors.New("target set does not exist")
	}
	operation.TargetSets[index].Targets = removeString(operation.TargetSets[index].Targets, target)
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("target", "target removed from set",
			operatorlog.Field{Name: "targetSet", Value: name},
			operatorlog.Field{Name: "target", Value: target},
		))
	}
	return nil
}

func (s *Store) addModule(operationName, chainName, moduleID, stepID string) (Step, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(operationName, chainName)
	chain.nextStep++
	step := Step{
		ID:       fmt.Sprintf("step-%d", chain.nextStep),
		ModuleID: moduleID,
		StepID:   strings.TrimSpace(stepID),
	}
	chain.Steps = append(chain.Steps, step)
	fields := []operatorlog.Field{
		operatorlog.Field{Name: "step", Value: step.ID},
		operatorlog.Field{Name: "module", Value: moduleID},
	}
	if step.StepID != "" {
		fields = append(fields, operatorlog.Field{Name: "providerStep", Value: step.StepID})
	}
	chain.Logs = append(chain.Logs, operatorlog.Info("chain", "module added", fields...))
	return step, nil
}

func (s *Store) setChainConfig(operationName, chainName, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(operationName, chainName)
	if chain.Config == nil {
		chain.Config = map[string]string{}
	}
	chain.Config[key] = value
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "chain config set",
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) unsetChainConfig(operationName, chainName, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(operationName, chainName)
	delete(chain.Config, key)
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "chain config unset",
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) setTargetConfig(operationName, chainName, target, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if !hasString(operation.Targets, target) {
		return errors.New("target does not exist")
	}
	if operation.TargetConfigs == nil {
		operation.TargetConfigs = map[string]map[string]string{}
	}
	if operation.TargetConfigs[target] == nil {
		operation.TargetConfigs[target] = map[string]string{}
	}
	operation.TargetConfigs[target][key] = value
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("config", "target config set",
			operatorlog.Field{Name: "target", Value: target},
			operatorlog.Field{Name: "key", Value: key},
		))
	}
	return nil
}

func (s *Store) unsetTargetConfig(operationName, chainName, target, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	if !hasString(operation.Targets, target) {
		return errors.New("target does not exist")
	}
	delete(operation.TargetConfigs[target], key)
	if chainName != "" {
		chain := s.ensureChain(operationName, chainName)
		chain.Logs = append(chain.Logs, operatorlog.Info("config", "target config unset",
			operatorlog.Field{Name: "target", Value: target},
			operatorlog.Field{Name: "key", Value: key},
		))
	}
	return nil
}

func (s *Store) appendLog(operationName, chainName string, entries ...operatorlog.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(operationName, chainName)
	chain.Logs = append(chain.Logs, cloneEntries(entries)...)
	return nil
}

func (s *Store) snapshot(operationName, activeChain string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := s.ensureOperation(operationName)
	state := State{
		ActiveOperation: operation.Name,
		Operation:       operation.Name,
		ActiveChain:     activeChain,
		Chain:           activeChain,
		Targets:         append([]string(nil), operation.Targets...),
		TargetConfigs:   cloneTargetConfigs(operation.TargetConfigs),
		TargetSets:      cloneTargetSets(operation.TargetSets),
	}
	if activeChain != "" {
		if chain, ok := operation.chains[activeChain]; ok {
			state.Steps = cloneSteps(chain.Steps)
			state.Config = cloneStringMap(chain.Config)
			state.LogTopic = chain.LogTopic
		}
	}
	state.Chains = snapshotChains(operation)
	state.Operations = s.snapshotOperations()
	return state
}

func (s *Store) logs(operationName, activeChain string) []operatorlog.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if activeChain == "" {
		return nil
	}
	operation := s.ensureOperation(operationName)
	chain, ok := operation.chains[activeChain]
	if !ok {
		return nil
	}
	return cloneEntries(chain.Logs)
}

func (s *Store) export(activeOperation, activeChain string) PersistedState {
	s.mu.Lock()
	defer s.mu.Unlock()
	operations := make([]PersistedOperation, 0, len(s.operations))
	snapshots := s.snapshotOperations()
	for _, operation := range snapshots {
		operations = append(operations, PersistedOperation{
			Name:          operation.Name,
			Targets:       append([]string(nil), operation.Targets...),
			TargetConfigs: cloneTargetConfigs(operation.TargetConfigs),
			TargetSets:    cloneTargetSets(operation.TargetSets),
			Chains:        persistedChains(operation.Chains),
		})
	}
	state := PersistedState{
		ActiveOperation: activeOperation,
		ActiveChain:     activeChain,
		Operations:      operations,
	}
	if operation, ok := s.operations[activeOperation]; ok {
		state.Chains = persistedChains(snapshotChains(operation))
	}
	return state
}

func (s *Store) importState(state PersistedState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operations = map[string]*operationState{}
	if len(state.Operations) > 0 {
		for _, persistedOperation := range state.Operations {
			s.importOperation(persistedOperation)
		}
		return
	}
	operationName := normalizeOperation(state.ActiveOperation)
	if operationName == "" {
		operationName = DefaultOperation
	}
	s.importOperation(PersistedOperation{Name: operationName, Chains: state.Chains})
}

func (s *Store) importOperation(persistedOperation PersistedOperation) {
	name := normalizeOperation(persistedOperation.Name)
	if name == "" {
		name = DefaultOperation
	}
	operation := s.ensureOperation(name)
	operation.Targets = append([]string(nil), persistedOperation.Targets...)
	operation.TargetConfigs = cloneTargetConfigs(persistedOperation.TargetConfigs)
	operation.TargetSets = cloneTargetSets(persistedOperation.TargetSets)
	operation.chains = map[string]*Chain{}
	for _, persisted := range persistedOperation.Chains {
		chainName := normalizeName(persisted.Name)
		if chainName == "" {
			continue
		}
		chain := &Chain{
			Name:          chainName,
			Targets:       append([]string(nil), persisted.Targets...),
			Steps:         cloneSteps(persisted.Steps),
			Config:        cloneStringMap(persisted.Config),
			TargetConfigs: cloneTargetConfigs(persisted.TargetConfigs),
			LogTopic:      persisted.LogTopic,
			Logs:          cloneEntries(persisted.Logs),
			nextStep:      nextStep(persisted.Steps),
		}
		if chain.Config == nil {
			chain.Config = map[string]string{}
		}
		if chain.TargetConfigs == nil {
			chain.TargetConfigs = map[string]map[string]string{}
		}
		if chain.LogTopic == "" || strings.HasPrefix(chain.LogTopic, "chain/") {
			chain.LogTopic = logTopic(name, chainName)
		}
		operation.chains[chainName] = chain
		operation.importLegacyTargets(chain.Targets, chain.TargetConfigs)
		chain.Targets = nil
		chain.TargetConfigs = map[string]map[string]string{}
	}
}

func (s *Store) hasOperation(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.operations[normalizeOperation(name)]
	return ok
}

func (s *Store) hasChain(operationName, chainName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.operations[normalizeOperation(operationName)]
	if !ok {
		return false
	}
	_, ok = operation.chains[chainName]
	return ok
}

func (s *Store) ensureOperation(name string) *operationState {
	name = normalizeOperation(name)
	if name == "" {
		name = DefaultOperation
	}
	if s.operations == nil {
		s.operations = map[string]*operationState{}
	}
	if operation, ok := s.operations[name]; ok {
		return operation
	}
	operation := &operationState{
		Name:          name,
		TargetConfigs: map[string]map[string]string{},
		chains:        map[string]*Chain{},
	}
	s.operations[name] = operation
	return operation
}

func (s *Store) ensureChain(operationName, chainName string) *Chain {
	operation := s.ensureOperation(operationName)
	if chain, ok := operation.chains[chainName]; ok {
		return chain
	}
	chain := &Chain{
		Name:          chainName,
		Config:        map[string]string{},
		TargetConfigs: map[string]map[string]string{},
		LogTopic:      logTopic(operation.Name, chainName),
	}
	operation.chains[chainName] = chain
	return chain
}

func (s *Store) snapshotOperations() []Operation {
	operations := make([]Operation, 0, len(s.operations))
	for _, operation := range s.operations {
		operations = append(operations, Operation{
			Name:          operation.Name,
			Targets:       append([]string(nil), operation.Targets...),
			TargetConfigs: cloneTargetConfigs(operation.TargetConfigs),
			TargetSets:    cloneTargetSets(operation.TargetSets),
			Chains:        snapshotChains(operation),
		})
	}
	sort.Slice(operations, func(i, j int) bool {
		return operations[i].Name < operations[j].Name
	})
	return operations
}

func snapshotChains(operation *operationState) []Chain {
	chains := make([]Chain, 0, len(operation.chains))
	for _, chain := range operation.chains {
		chains = append(chains, cloneChain(*chain))
	}
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].Name < chains[j].Name
	})
	return chains
}

func persistedChains(chains []Chain) []PersistedChain {
	persisted := make([]PersistedChain, 0, len(chains))
	for _, chain := range chains {
		persisted = append(persisted, PersistedChain{
			Name:          chain.Name,
			Targets:       append([]string(nil), chain.Targets...),
			Steps:         cloneSteps(chain.Steps),
			Config:        cloneStringMap(chain.Config),
			TargetConfigs: cloneTargetConfigs(chain.TargetConfigs),
			LogTopic:      chain.LogTopic,
			Logs:          cloneEntries(chain.Logs),
		})
	}
	return persisted
}

func cloneChain(chain Chain) Chain {
	chain.Targets = append([]string(nil), chain.Targets...)
	chain.Steps = cloneSteps(chain.Steps)
	chain.Config = cloneStringMap(chain.Config)
	chain.TargetConfigs = cloneTargetConfigs(chain.TargetConfigs)
	chain.Logs = cloneEntries(chain.Logs)
	return chain
}

func cloneSteps(steps []Step) []Step {
	return append([]Step(nil), steps...)
}

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		out[target] = cloneStringMap(config)
	}
	return out
}

func cloneTargetSets(values []TargetSet) []TargetSet {
	out := make([]TargetSet, 0, len(values))
	for _, value := range values {
		out = append(out, TargetSet{
			Name:    value.Name,
			Targets: append([]string(nil), value.Targets...),
		})
	}
	return out
}

func cloneEntries(entries []operatorlog.Entry) []operatorlog.Entry {
	out := make([]operatorlog.Entry, 0, len(entries))
	for _, entry := range entries {
		entry.Fields = append([]operatorlog.Field(nil), entry.Fields...)
		out = append(out, entry)
	}
	return out
}

func normalizeName(name string) string {
	return strings.TrimSpace(name)
}

func normalizeOperation(name string) string {
	return strings.TrimSpace(name)
}

func logTopic(operation, chain string) string {
	operation = normalizeOperation(operation)
	if operation == "" {
		operation = DefaultOperation
	}
	return "operation/" + operation + "/chain/" + chain + "/logs"
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func removeString(values []string, remove string) []string {
	out := values[:0]
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}

func findTargetSet(values []TargetSet, name string) int {
	for i, value := range values {
		if value.Name == name {
			return i
		}
	}
	return -1
}

func (o *operationState) importLegacyTargets(targets []string, configs map[string]map[string]string) {
	if o.TargetConfigs == nil {
		o.TargetConfigs = map[string]map[string]string{}
	}
	for _, target := range targets {
		if !hasString(o.Targets, target) {
			o.Targets = append(o.Targets, target)
		}
		if _, ok := o.TargetConfigs[target]; !ok {
			o.TargetConfigs[target] = map[string]string{}
		}
		for key, value := range configs[target] {
			o.TargetConfigs[target][key] = value
		}
	}
}

func nextStep(steps []Step) int {
	next := len(steps)
	for _, step := range steps {
		if value, ok := strings.CutPrefix(step.ID, "step-"); ok {
			if number, err := strconv.Atoi(value); err == nil && number > next {
				next = number
			}
		}
	}
	return next
}
