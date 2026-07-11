// Package godeps anchors Go modules used by Bazel targets outside the nested
// core module. It is dependency metadata, not production code.
package godeps

import (
	_ "github.com/bazelbuild/rules_go/go/runfiles"
	_ "github.com/c-bata/go-prompt"
	_ "github.com/charmbracelet/lipgloss"
	_ "github.com/charmbracelet/x/term"
	_ "github.com/jfjallid/go-smb/gss"
	_ "github.com/jfjallid/go-smb/ntlmssp"
	_ "github.com/jfjallid/go-smb/spnego"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "golang.org/x/sys/unix"
	_ "golang.org/x/tools/go/analysis/passes/nilness"
)
