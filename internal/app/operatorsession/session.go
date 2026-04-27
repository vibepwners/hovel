package operatorsession

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

type Chain struct {
	Name     string
	Targets  []string
	LogTopic string
	Logs     []operatorlog.Entry
}

type State struct {
	ActiveChain string
	Chain       string
	Targets     []string
	LogTopic    string
	Chains      []Chain
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
	chain.Targets = append(chain.Targets, target)
	return nil
}

func (s *Store) clearTargets(chainName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.ensureChain(chainName)
	chain.Targets = nil
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

func (s *Store) ensureChain(name string) *Chain {
	if s.chains == nil {
		s.chains = map[string]*Chain{}
	}
	if chain, ok := s.chains[name]; ok {
		return chain
	}
	chain := &Chain{Name: name, LogTopic: logTopic(name)}
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
	chain.Logs = cloneEntries(chain.Logs)
	return chain
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
