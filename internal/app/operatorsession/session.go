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
}

type State struct {
	ActiveChain   string
	Chain         string
	Targets       []string
	Steps         []Step
	Config        map[string]string
	TargetConfigs map[string]map[string]string
	LogTopic      string
	Chains        []Chain
}

type PersistedState struct {
	ActiveChain string           `json:"activeChain"`
	Chains      []PersistedChain `json:"chains"`
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
	mu     sync.Mutex
	chains map[string]*Chain
}

func New() *Session {
	return NewWithStore(NewStore())
}

func NewStore() *Store {
	return &Store{chains: map[string]*Chain{}}
}

type Session struct {
	mu          sync.Mutex
	activeChain string
	store       *Store
}

func NewWithStore(store *Store) *Session {
	if store == nil {
		store = NewStore()
	}
	return &Session{store: store}
}

func (s *Session) CreateChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	return s.chainStore().createChain(name)
}

func (s *Session) UseChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	if err := s.chainStore().createChain(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeChain = name
	return nil
}

func (s *Session) RenameChain(oldName, newName string) error {
	oldName = normalizeName(oldName)
	newName = normalizeName(newName)
	if oldName == "" || newName == "" {
		return errors.New("chain is required")
	}
	if err := s.chainStore().renameChain(oldName, newName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChain == oldName {
		s.activeChain = newName
	}
	return nil
}

func (s *Session) DeleteChain(name string) error {
	name = normalizeName(name)
	if name == "" {
		return errors.New("chain is required")
	}
	if err := s.chainStore().deleteChain(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChain == name {
		s.activeChain = ""
	}
	return nil
}

func (s *Session) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("target is required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().addTarget(activeChain, target)
}

func (s *Session) ClearTargets() {
	activeChain := s.active()
	if activeChain == "" {
		return
	}
	s.chainStore().clearTargets(activeChain)
}

func (s *Session) AddModule(moduleID string) (Step, error) {
	moduleID = strings.TrimSpace(moduleID)
	if moduleID == "" {
		return Step{}, errors.New("module is required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return Step{}, errors.New("active chain is required")
	}
	return s.chainStore().addModule(activeChain, moduleID)
}

func (s *Session) SetChainConfig(key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return errors.New("config key and value are required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().setChainConfig(activeChain, key, value)
}

func (s *Session) UnsetChainConfig(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("config key is required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().unsetChainConfig(activeChain, key)
}

func (s *Session) SetTargetConfig(target, key, value string) error {
	target = strings.TrimSpace(target)
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if target == "" || key == "" || value == "" {
		return errors.New("target, config key, and value are required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().setTargetConfig(activeChain, target, key, value)
}

func (s *Session) UnsetTargetConfig(target, key string) error {
	target = strings.TrimSpace(target)
	key = strings.TrimSpace(key)
	if target == "" || key == "" {
		return errors.New("target and config key are required")
	}
	activeChain := s.active()
	if activeChain == "" {
		return errors.New("active chain is required")
	}
	return s.chainStore().unsetTargetConfig(activeChain, target, key)
}

func (s *Session) AppendLog(entries ...operatorlog.Entry) error {
	activeChain := s.active()
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
	return s.chainStore().appendLog(name, entries...)
}

func (s *Session) Snapshot() State {
	return s.chainStore().snapshot(s.active())
}

func (s *Session) ActiveLogs() []operatorlog.Entry {
	return s.chainStore().logs(s.active())
}

func (s *Session) Export() PersistedState {
	return s.chainStore().export(s.active())
}

func (s *Session) Import(state PersistedState) {
	s.chainStore().importState(state)
	activeChain := normalizeName(state.ActiveChain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if activeChain != "" && s.store.hasChain(activeChain) {
		s.activeChain = activeChain
		return
	}
	s.activeChain = ""
}

func (s *Session) active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeChain
}

func (s *Session) chainStore() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = NewStore()
	}
	return s.store
}

func (s *Store) createChain(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureChain(name)
	return nil
}

func (s *Store) renameChain(oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain, ok := s.chains[oldName]
	if !ok {
		return errors.New("chain does not exist")
	}
	if oldName == newName {
		return nil
	}
	if _, exists := s.chains[newName]; exists {
		return errors.New("chain already exists")
	}
	delete(s.chains, oldName)
	chain.Name = newName
	chain.LogTopic = logTopic(newName)
	s.chains[newName] = chain
	return nil
}

func (s *Store) deleteChain(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.chains[name]; !ok {
		return errors.New("chain does not exist")
	}
	delete(s.chains, name)
	return nil
}

func (s *Store) addTarget(chainName, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	if !hasString(chain.Targets, target) {
		chain.TargetConfigs[target] = map[string]string{}
		chain.Targets = append(chain.Targets, target)
	}
	chain.Logs = append(chain.Logs, operatorlog.Info("target", "target added",
		operatorlog.Field{Name: "target", Value: target},
	))
	return nil
}

func (s *Store) clearTargets(chainName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	chain.Targets = nil
	chain.TargetConfigs = map[string]map[string]string{}
	chain.Logs = append(chain.Logs, operatorlog.Info("target", "targets cleared"))
}

func (s *Store) addModule(chainName, moduleID string) (Step, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	chain.nextStep++
	step := Step{
		ID:       fmt.Sprintf("step-%d", chain.nextStep),
		ModuleID: moduleID,
	}
	chain.Steps = append(chain.Steps, step)
	chain.Logs = append(chain.Logs, operatorlog.Info("chain", "module added",
		operatorlog.Field{Name: "step", Value: step.ID},
		operatorlog.Field{Name: "module", Value: moduleID},
	))
	return step, nil
}

func (s *Store) setChainConfig(chainName, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	if chain.Config == nil {
		chain.Config = map[string]string{}
	}
	chain.Config[key] = value
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "chain config set",
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) unsetChainConfig(chainName, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	delete(chain.Config, key)
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "chain config unset",
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) setTargetConfig(chainName, target, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	if !hasString(chain.Targets, target) {
		return errors.New("target does not exist")
	}
	if chain.TargetConfigs == nil {
		chain.TargetConfigs = map[string]map[string]string{}
	}
	if chain.TargetConfigs[target] == nil {
		chain.TargetConfigs[target] = map[string]string{}
	}
	chain.TargetConfigs[target][key] = value
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "target config set",
		operatorlog.Field{Name: "target", Value: target},
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) unsetTargetConfig(chainName, target, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	if !hasString(chain.Targets, target) {
		return errors.New("target does not exist")
	}
	delete(chain.TargetConfigs[target], key)
	chain.Logs = append(chain.Logs, operatorlog.Info("config", "target config unset",
		operatorlog.Field{Name: "target", Value: target},
		operatorlog.Field{Name: "key", Value: key},
	))
	return nil
}

func (s *Store) appendLog(chainName string, entries ...operatorlog.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	chain.Logs = append(chain.Logs, cloneEntries(entries)...)
	return nil
}

func (s *Store) snapshot(activeChain string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := State{
		ActiveChain: activeChain,
		Chain:       activeChain,
	}
	if activeChain != "" {
		if chain, ok := s.chains[activeChain]; ok {
			state.Targets = append([]string(nil), chain.Targets...)
			state.Steps = cloneSteps(chain.Steps)
			state.Config = cloneStringMap(chain.Config)
			state.TargetConfigs = cloneTargetConfigs(chain.TargetConfigs)
			state.LogTopic = chain.LogTopic
		}
	}
	state.Chains = s.snapshotChains()
	return state
}

func (s *Store) logs(activeChain string) []operatorlog.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if activeChain == "" {
		return nil
	}
	chain, ok := s.chains[activeChain]
	if !ok {
		return nil
	}
	return cloneEntries(chain.Logs)
}

func (s *Store) export(activeChain string) PersistedState {
	s.mu.Lock()
	defer s.mu.Unlock()
	chains := make([]PersistedChain, 0, len(s.chains))
	snapshots := make([]Chain, 0, len(s.chains))
	for _, chain := range s.chains {
		snapshots = append(snapshots, cloneChain(*chain))
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Name < snapshots[j].Name
	})
	for _, chain := range snapshots {
		chains = append(chains, PersistedChain{
			Name:          chain.Name,
			Targets:       append([]string(nil), chain.Targets...),
			Steps:         cloneSteps(chain.Steps),
			Config:        cloneStringMap(chain.Config),
			TargetConfigs: cloneTargetConfigs(chain.TargetConfigs),
			LogTopic:      chain.LogTopic,
			Logs:          cloneEntries(chain.Logs),
		})
	}
	return PersistedState{
		ActiveChain: activeChain,
		Chains:      chains,
	}
}

func (s *Store) importState(state PersistedState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chains = map[string]*Chain{}
	for _, persisted := range state.Chains {
		name := normalizeName(persisted.Name)
		if name == "" {
			continue
		}
		chain := &Chain{
			Name:          name,
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
		if chain.LogTopic == "" {
			chain.LogTopic = logTopic(name)
		}
		s.chains[name] = chain
	}
}

func (s *Store) hasChain(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.chains[name]
	return ok
}

func (s *Store) ensureChain(name string) *Chain {
	if s.chains == nil {
		s.chains = map[string]*Chain{}
	}
	if chain, ok := s.chains[name]; ok {
		return chain
	}
	chain := &Chain{
		Name:          name,
		Config:        map[string]string{},
		TargetConfigs: map[string]map[string]string{},
		LogTopic:      logTopic(name),
	}
	s.chains[name] = chain
	return chain
}

func (s *Store) snapshotChains() []Chain {
	chains := make([]Chain, 0, len(s.chains))
	for _, chain := range s.chains {
		chains = append(chains, cloneChain(*chain))
	}
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].Name < chains[j].Name
	})
	return chains
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

func logTopic(chain string) string {
	return "chain/" + chain + "/logs"
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
