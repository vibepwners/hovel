//go:build tools

// Package linttools anchors Go analyzer modules used by Bazel.
package linttools

import _ "golang.org/x/tools/go/analysis/passes/nilness"
