package operatorsession

import (
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

func TestSessionCreatesUsesListsAndDeletesChains(t *testing.T) {
	session := New()

	if err := session.CreateChain("second"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("first"); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if state.ActiveChain != "first" {
		t.Fatalf("active chain = %q, want first", state.ActiveChain)
	}
	if len(state.Chains) != 2 {
		t.Fatalf("chain count = %d, want 2", len(state.Chains))
	}
	if state.Chains[0].Name != "first" || state.Chains[1].Name != "second" {
		t.Fatalf("chains = %#v, want sorted first/second", state.Chains)
	}
	if state.LogTopic != "operation/default/chain/first/logs" {
		t.Fatalf("log topic = %q, want operation/default/chain/first/logs", state.LogTopic)
	}

	if err := session.DeleteChain("first"); err != nil {
		t.Fatal(err)
	}
	if session.Snapshot().ActiveChain != "" {
		t.Fatal("deleted active chain should clear active chain")
	}
}

func TestSessionTargetsAreOwnedByOperation(t *testing.T) {
	session := New()
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}

	if err := session.AddTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}

	beta := session.Snapshot()
	if beta.Chain != "beta" {
		t.Fatalf("chain = %q, want beta", beta.Chain)
	}
	if got, want := beta.Targets, []string{"mock://ops", "mock://alpha", "mock://beta"}; !equalStrings(got, want) {
		t.Fatalf("beta targets = %#v", beta.Targets)
	}

	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	alpha := session.Snapshot()
	if got, want := alpha.Targets, []string{"mock://ops", "mock://alpha", "mock://beta"}; !equalStrings(got, want) {
		t.Fatalf("alpha targets = %#v", alpha.Targets)
	}
	if len(alpha.Chains) != 2 {
		t.Fatalf("chains = %#v, want alpha and beta", alpha.Chains)
	}
	for _, chain := range alpha.Chains {
		if len(chain.Targets) != 0 {
			t.Fatalf("chain %s owns targets %#v, want none", chain.Name, chain.Targets)
		}
	}
}

func TestSessionRenamesChainWithOwnedTargetsAndLogs(t *testing.T) {
	session := New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLog(operatorlog.Info("alpha", "before rename")); err != nil {
		t.Fatal(err)
	}

	if err := session.RenameChain("alpha", "renamed"); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if state.ActiveChain != "renamed" {
		t.Fatalf("active chain = %q, want renamed", state.ActiveChain)
	}
	if len(state.Targets) != 1 || state.Targets[0] != "mock://alpha" {
		t.Fatalf("targets = %#v", state.Targets)
	}
	if state.LogTopic != "operation/default/chain/renamed/logs" {
		t.Fatalf("log topic = %q, want operation/default/chain/renamed/logs", state.LogTopic)
	}
	if logs := session.ActiveLogs(); !hasLogMessage(logs, "before rename") {
		t.Fatalf("logs = %#v", logs)
	}
}

func TestSessionRejectsBlankChainAndTarget(t *testing.T) {
	session := New()

	if err := session.UseChain(" "); err == nil {
		t.Fatal("expected blank chain error")
	}
	if err := session.AddTarget(" "); err == nil {
		t.Fatal("expected blank target error")
	}
}

func TestSessionRequiresActiveOperationForTargets(t *testing.T) {
	session := New()

	if err := session.AddTarget("mock://target"); err == nil {
		t.Fatal("expected active operation error")
	}
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target"); err != nil {
		t.Fatalf("target add after operation use failed: %v", err)
	}
}

func TestSessionClearsOperationTargets(t *testing.T) {
	session := New()
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}

	session.ClearTargets()

	state := session.Snapshot()
	if targets := state.Targets; len(targets) != 0 {
		t.Fatalf("operation targets = %#v, want none", targets)
	}
	if configs := state.TargetConfigs; len(configs) != 0 {
		t.Fatalf("operation target configs = %#v, want none", configs)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if targets := session.Snapshot().Targets; len(targets) != 0 {
		t.Fatalf("alpha snapshot targets = %#v, want none", targets)
	}
}

func TestSessionTargetSetsAreOwnedByOperation(t *testing.T) {
	session := New()
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}
	if err := session.CreateTargetSet("xp-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("xp-lab", "mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("xp-lab", "mock://beta"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha-chain"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta-chain"); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if len(state.TargetSets) != 1 {
		t.Fatalf("target sets = %#v", state.TargetSets)
	}
	if state.TargetSets[0].Name != "xp-lab" || !equalStrings(state.TargetSets[0].Targets, []string{"mock://alpha", "mock://beta"}) {
		t.Fatalf("target set = %#v", state.TargetSets[0])
	}
}

func TestSessionLogsAreScopedToActiveChain(t *testing.T) {
	session := New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLog(operatorlog.Info("alpha", "only alpha")); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if logs := session.ActiveLogs(); len(logs) != 0 {
		t.Fatalf("beta logs = %#v, want none", logs)
	}
	if err := session.AppendLog(operatorlog.Info("beta", "only beta")); err != nil {
		t.Fatal(err)
	}
	if logs := session.ActiveLogs(); len(logs) != 1 || logs[0].Message != "only beta" {
		t.Fatalf("beta logs = %#v", logs)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if logs := session.ActiveLogs(); len(logs) != 1 || logs[0].Message != "only alpha" {
		t.Fatalf("alpha logs = %#v", logs)
	}
}

func TestSessionCanAppendLogsToNamedChainWithoutChangingActiveChain(t *testing.T) {
	session := New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLogToChain("beta", operatorlog.Info("beta", "from explicit chain")); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if state.ActiveChain != "alpha" {
		t.Fatalf("active chain = %q, want alpha", state.ActiveChain)
	}
	if logs := session.ActiveLogs(); len(logs) != 0 {
		t.Fatalf("alpha logs = %#v, want none", logs)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if logs := session.ActiveLogs(); len(logs) != 1 || logs[0].Message != "from explicit chain" {
		t.Fatalf("beta logs = %#v", logs)
	}
}

func TestSessionsShareChainStoreWithIndependentActiveChains(t *testing.T) {
	store := NewStore()
	alphaClient := NewWithStore(store)
	betaClient := NewWithStore(store)
	alphaObserver := NewWithStore(store)

	if err := alphaClient.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := betaClient.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := alphaObserver.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := alphaClient.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := alphaClient.AppendLog(operatorlog.Info("alpha", "shared alpha log")); err != nil {
		t.Fatal(err)
	}
	if err := betaClient.AppendLog(operatorlog.Info("beta", "hidden beta log")); err != nil {
		t.Fatal(err)
	}

	if alphaClient.Snapshot().ActiveChain != "alpha" {
		t.Fatalf("alpha client active chain = %q", alphaClient.Snapshot().ActiveChain)
	}
	if betaClient.Snapshot().ActiveChain != "beta" {
		t.Fatalf("beta client active chain = %q", betaClient.Snapshot().ActiveChain)
	}
	if targets := alphaObserver.Snapshot().Targets; len(targets) != 1 || targets[0] != "mock://alpha" {
		t.Fatalf("alpha observer targets = %#v", targets)
	}
	if logs := alphaObserver.ActiveLogs(); !hasLogMessage(logs, "shared alpha log") {
		t.Fatalf("alpha observer logs = %#v", logs)
	}
	if logs := betaClient.ActiveLogs(); len(logs) != 1 || logs[0].Message != "hidden beta log" {
		t.Fatalf("beta client logs = %#v", logs)
	}
}

func TestOperationsSegmentChainsAndRestoreClientActiveChain(t *testing.T) {
	store := NewStore()
	client := NewWithStore(store)
	observer := NewWithStore(store)

	if err := client.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := client.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := client.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := client.UseOperation("afterparty"); err != nil {
		t.Fatal(err)
	}
	if err := client.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := client.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}
	if err := client.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}

	state := client.Snapshot()
	if state.ActiveOperation != "redteam-lab" || state.ActiveChain != "alpha" {
		t.Fatalf("client attachment = %s/%s, want redteam-lab/alpha", state.ActiveOperation, state.ActiveChain)
	}
	if len(state.Targets) != 1 || state.Targets[0] != "mock://alpha" {
		t.Fatalf("redteam-lab alpha targets = %#v", state.Targets)
	}

	if err := observer.UseOperation("afterparty"); err != nil {
		t.Fatal(err)
	}
	if err := observer.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if targets := observer.Snapshot().Targets; len(targets) != 1 || targets[0] != "mock://beta" {
		t.Fatalf("afterparty beta targets = %#v", targets)
	}
}

func TestSessionExportsAndImportsState(t *testing.T) {
	session := New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLog(operatorlog.Info("alpha", "persisted log")); err != nil {
		t.Fatal(err)
	}

	imported := New()
	imported.Import(session.Export())

	state := imported.Snapshot()
	if state.ActiveChain != "alpha" {
		t.Fatalf("active chain = %q, want alpha", state.ActiveChain)
	}
	if len(state.Steps) != 1 || state.Steps[0].ID != "step-1" {
		t.Fatalf("steps = %#v", state.Steps)
	}
	if logs := imported.ActiveLogs(); !hasLogMessage(logs, "persisted log") {
		t.Fatalf("logs = %#v", logs)
	}
	step, err := imported.AddModule("mock-survey")
	if err != nil {
		t.Fatal(err)
	}
	if step.ID != "step-2" {
		t.Fatalf("next step ID = %q, want step-2", step.ID)
	}
}

func TestSessionTracksModulesAndTypedConfigByChain(t *testing.T) {
	session := New()
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	step, err := session.AddModule("mock-exploit")
	if err != nil {
		t.Fatal(err)
	}
	if step.ID != "step-1" || step.ModuleID != "mock-exploit" {
		t.Fatalf("step = %#v", step)
	}
	if err := session.SetChainConfig("operator.confirmed_lab", "true"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://target"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://target", "target.host", "router-01"); err != nil {
		t.Fatal(err)
	}
	if err := session.SetTargetConfig("mock://target", "target.port", "22"); err != nil {
		t.Fatal(err)
	}

	state := session.Snapshot()
	if len(state.Steps) != 1 || state.Steps[0].ID != "step-1" {
		t.Fatalf("steps = %#v", state.Steps)
	}
	if state.Config["operator.confirmed_lab"] != "true" {
		t.Fatalf("chain config = %#v", state.Config)
	}
	if state.TargetConfigs["mock://target"]["target.port"] != "22" {
		t.Fatalf("target config = %#v", state.TargetConfigs)
	}
	if logs := session.ActiveLogs(); !hasLogMessage(logs, "module added") || !hasLogMessage(logs, "target config set") {
		t.Fatalf("logs = %#v", logs)
	}
}

func hasLogMessage(logs []operatorlog.Entry, message string) bool {
	for _, entry := range logs {
		if entry.Message == message {
			return true
		}
	}
	return false
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
