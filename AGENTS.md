# Agent instructions for Hovel

These instructions apply to any AI agent or automation working in this
repository. (`CLAUDE.md` is a symlink to this file.)

## The one rule for the build system

**Always invoke the build system through [Aspect CLI](https://aspect.build/cli)
(`aspect <command>`). Never call `bazel`, `gofmt`, `uv`, or `lefthook` directly.**

The checked-in `.aspect/*.axl` files are the single source of truth for how the
project is built, tested, linted, formatted, packaged, reported, and run. CI,
the git hooks, the docs, and agents all go through them. `.aspect/version.axl`
pins the supported Aspect CLI version. If something cannot be done with an
existing command, add or fix an AXL command rather than running the underlying
tool ad hoc.

Run `aspect help` to see everything available.

## How the Aspect command layer works

- Top-level Hovel workflows are programmable AXL tasks: `hovel-check`,
  `hovel-format`, `hovel`, `hovel-report`, `hovel-site`, `hovel-release`, and
  `hovel-hooks`. Prefer these over spelling out their constituent targets.
- The standard `aspect build`, `aspect test`, and `aspect run` tasks remain the
  escape hatch for a narrow Bazel target that does not need a repository-level
  workflow. Pass Bazel options with `--bazel-flag=...`; pass arguments to a run
  target after `--`.
- The repository contains a root Bazel workspace plus the nested `core`
  workspace. AXL owns the correct working directory and target labels. Do not
  translate `@hovel_core//...` labels or manually change directories to imitate
  an AXL workflow.
- CI automatically receives `--config=ci`. Local execution may select `local`,
  `nativelink`, `nativelink-minimal`, or `buildbuddy` in
  `.hovel-bazel-config`. `HOVEL_BAZEL_ARGS` overrides that selection, and
  `HOVEL_BAZEL_STARTUP_ARGS` supplies startup flags. Do not bake a developer's
  local cache or remote-execution choice into commands or BUILD files.
- `aspect run` is configured to run from the Bazel workspace root so
  materializers have a predictable working directory.

## Shell in the build graph

Do not add shell scripts to the build, lint, test, docs, or demo pipeline by
default. Hovel uses Bazel/Starlark for declared build actions and Python for
non-trivial repository tooling. Shell is acceptable only when the shell itself
is the thing being demonstrated or operated, such as VHS terminal recordings,
Docker entrypoints, or one-off lab operator scripts.

When a check can be cached, model it as a Bazel target with explicit inputs and
outputs instead of discovering files from shell at execution time. When a task
must materialize generated artifacts back into the working tree (`_site/`,
`docs/demo/out/`, `modules/examples/bin/`), prefer an `aspect run` invocation of
a Python materializer with declared Bazel data dependencies. Do not call Bazel
from helper scripts.

Build, test, lint, docs, and demo tools should be Bazel-managed execution
inputs whenever practical: pinned archives, pip wheels, Go/Rust toolchains, or
custom toolchains/rules. Do not add new `PATH` lookups, `go install`, `uv tool
install`, Homebrew, or apt-installed CLIs for tools that can reasonably be
declared in Bazel. Host tools are acceptable only for real host services or
system boundaries that Bazel should not own, such as Docker, Wine, tmux, ttyd,
or ffmpeg until they have a pinned execution toolchain.

## Common tasks

| Command | What it does |
| --- | --- |
| `aspect help` | List all commands. |
| `aspect build` | Build the core Hovel binary workspace. |
| `aspect build @hovel_core//cmd/hovel` | Build the Hovel CLI target. |
| `aspect test` | Run core Hovel binary workspace tests. |
| `aspect test @hovel_core//internal/domain/...` | Run specific core tests from the root workspace. |
| `aspect hovel-check` | Run the full non-publishing gate: repo, core, SDKs, examples, modules, and docs. |
| `aspect hovel-check <scope>` | Run one of `repo`, `core`, `sdk`, `module-examples`, `modules`, `docs`, or `agent`. |
| `aspect hovel-format` | Format all wired Go, Python, Rust, Gazelle, SDK, and module slices. |
| `aspect test --coverage ...` | Collect coverage for explicitly selected test targets. Repository ratchets live in `hovel-check`. |
| `aspect hovel <mode> [args]` | Run `cli`, `daemon`, `mcp`, `status`, `init`, `throw`, or `session` against the development workspace. |
| `aspect run //docs/tools/docs:stage_site` | Build and materialize the docs site to `_site/`. |
| `aspect hovel-check docs` | Build and validate the hermetic Astro docs artifact. |
| `aspect hovel-site` | Run Astro HMR on port 4321, including generated report evidence when present. |
| `aspect hovel-site tidewave` | Run Astro HMR with the localhost-only Tidewave MCP endpoint at `/tidewave/mcp`. |
| `aspect hovel-site preview` | Rebuild the deterministic assembled site and serve `_site/` on port 4322. |
| `aspect hovel-report` | Run report-producing tests and build `_site/` with the latest evidence. |
| `aspect hovel-release <kind>` | Build (without publishing) `hovel`, `sdk`, `modules`, `picblobs`, `picblobs-cli`, or `agent` artifacts. |
| `aspect hovel-hooks` | Install or refresh the repository hooks. |

## Definition of done

Before considering a code change complete, run the strongest Aspect-backed gate
available for the checked-out slices. Run **`aspect hovel-check`** from a full
checkout. Use the narrowest applicable `aspect hovel-check <scope>` while
iterating or when only that slice is present, and report which narrower gate was
used. The core scope covers formatting checks, golangci-lint, Gazelle, build,
tests, race, fuzz smoke, and coverage ratchets. The full gate additionally
covers repository policy, all SDKs, module examples, modules, and docs.

If you added, moved, or removed Go files or imports, run **`aspect hovel-format`** so
`gofmt` and Gazelle-generated `BUILD.bazel` files are up to date; otherwise
`aspect hovel-check core` will fail on the Gazelle diff check. When you add a new core test
target, also add it to the `test_suite` in `core/BUILD.bazel`.

## Compatibility contracts

Hovel is working toward 1.0 without breaking any currently functioning module.
Treat the existing module protocol and public Go, Python, and Rust SDK behavior
as an essential backwards-compatibility contract:

- A module that works against today's interfaces must continue to build,
  connect, advertise capabilities, receive configuration, execute, and return
  results while the 1.0 contracts are formalized.
- Change scaffolding, adapters, and generated surfaces before changing module
  source or public SDK shapes. Preserve wire names, prepared values, defaults,
  optional behavior, error semantics, and defensive-copy boundaries.
- Go-side and SDK-side compatibility branch ratchets and cross-language fixtures
  are release evidence, not incidental unit tests. New public branches require
  tests and must remain visible in the generated site report.
- Human/agent operator parity is also a contract. Canonical capabilities are
  registered and exercised semantically through the human command path and
  typed MCP tools against the same daemon-owned application services. Adding a
  human capability without an agent route, or bypassing typed MCP semantics via
  a generic command escape hatch, is a parity regression.
- Post-exploitation APIs must remain typed and capability-driven. Payload
  artifacts, Mesh/PKI integration, exploit handoff, tasks, operations, and
  session formation must preserve auditability and current provider behavior as
  those contracts move toward versioned 1.0 surfaces.

## Integration decisions

Use [Integration Decisions](docs/site/src/content/spec/integration-decisions.html)
when changing storage ownership, retained-session control, frontend refresh, or
integration contracts. In particular:

- Keep security handles alive with the resource they protect; preserve identity
  checks and test cross-process lock behavior when changing descriptor cleanup.
- Bound diagnostic history independently of live event delivery and session
  control. Preserve credential suppression, byte limits, and callback errors.
- Fetch authoritative state before replacing derived UI state; retain the last
  usable state on fetch failure and reuse existing refresh triggers.
- Restore terminal presentation and modes after attachment output stops; keep
  cleanup out of remote input, redirected output, and enclosing frontends.
- Trace existing public session dispatch before adding APIs or payload records.
  Session command results are not automatically confirmed throws or persisted
  output artifacts.
- Distinguish accepted-workflow defects from deferred features. Record exact
  revisions and gate scopes; an observation test asserting a defect is not a fix.
- Separate upstream integration, official release availability, and downstream
  adoption. Do not remove downstream workarounds based on a source merge alone.

## Docs authoring

Agents are expected to edit docs as literal HTML fragments under
`docs/site/src/content/`. Do not edit `_site/`, generated API reference output,
or reintroduce complete HTML documents into content files.

Every content file starts with one JSON metadata comment, followed by ordinary
HTML containing exactly one page-level `h1`:

```html
<!-- hovel-doc: {"title":"Example","group":"Foundations","order":120,"navTitle":"Example"} -->
<article>
  <h1>Example</h1>
  <p>Page content.</p>
</article>
```

- The path below `src/content/` determines the output URL. For example,
  `spec/example.html` builds as `_site/spec/example.html`.
- `group` and `order` place the page in generated contents, sidebar, chapter
  numbering, and previous/next navigation. Book groups are `Foundations`,
  `Runtime Platform`, `Operator Experience`, `Module Development`,
  `Engineering`, and `Reference`; `Contents` is reserved for `spec/index.html`.
  Orders must be unique within a group. Never write chapter or section numbers
  by hand. `navTitle` and `description` are optional.
- Write normal HTML. Inline browser JavaScript is allowed, and shared scripts,
  styles, images, or other static files belong under `docs/site/public/`.
- Global chrome lives in `src/components/` and `src/layouts/`. Change it once
  there; never copy headers, sidebars, footers, or page navigation into content.
- Module overview pages live at `src/content/modules/<module>/index.html` and
  additionally declare `moduleOrder`, `moduleType`, `moduleStatus`, and
  `description`. Use the module id as `group` on every page in its document set;
  Astro generates module/document numbering and all module navigation.
- Search is generated automatically from page metadata and body text. Keep
  titles and optional descriptions concrete so client-side search results stay
  useful; do not hand-maintain a separate search index.
- API landing metadata lives in `src/lib/apiReferences.ts`. Astro owns the API
  landing pages and shared Hovel chrome; generated Sphinx, pkgsite, and rustdoc
  interiors keep their native navigation and must not reimplement that chrome.
- The daemon OpenAPI source lives only at
  `docs/site/spec/reference/daemon-rpc.openapi.json`. The Bazel
  `//docs/site:daemon_rpc_openapi` target publishes it into Astro's
  `public/spec/reference/` path; never check in or edit a second public copy.
- The home page contains exactly one
  `<div data-hovel-component="demo-carousel"></div>` marker. Its reusable Astro
  component is `src/components/DemoCarousel.astro`, while the ordered demo data
  lives in `src/pages/index.astro`.
- Keep the build hermetic: do not add CDN assets, runtime network dependencies,
  or host `node`, `npm`, `pnpm`, or Python package assumptions. Update
  dependencies with the Bazel-managed dependency targets through `aspect run`;
  refresh both the checked-in JavaScript and hashed Python locks.
- After docs changes, run `aspect hovel-check docs`. Use `aspect run //docs/tools/docs:stage_site` when the root
  `_site/` materialization is required.
- Test evidence is generated after Bazel finishes. Use `aspect hovel-report` when
  `_site/reports/tests/latest/` must contain the latest monorepo test report.
- `aspect hovel-site` is the normal authoring command. It provides Astro HMR and
  serves ambient `.test-report/evidence/` through development-only middleware
  with `no-store` caching. After `aspect hovel-report`, refresh the report page
  to read the new JSON, logs, XML, artifacts, coverage, and linter evidence. Do
  not copy that evidence into `docs/site/public/`.
- The HMR modes run the Bazel-managed Astro binary against the working-tree
  `docs/site/` root. Ordinary content, component, layout, style, and public
  asset edits are visible without restarting Aspect. Restart after changing
  Bazel/AXL wiring, dependencies, or Astro startup configuration.
- `aspect hovel-site preview` stages the deterministic checked-in site before
  serving it; it intentionally does not attach ambient report evidence. Use the
  `_site/` produced by `aspect hovel-report` when inspecting the exact
  evidence-backed publication artifact.
- The normal docs staging target is deterministic and does not consume ambient
  `.test-report/` files. Astro owns the report HTML; report builds attach only
  generated JSON, logs, XML, and artifacts.
- Every assembled Pages artifact contains a deterministic site revision. An
  open deployed page polls that same-origin revision and reloads after a newer
  successful Pages deployment becomes visible. Local uncommitted changes still
  require a commit, push, successful CI run, and Pages promotion before they can
  affect the hosted site.
- CI uploads the evidence-backed `_site/` from `aspect hovel-report` as the
  `docs-site` artifact. The Pages workflow promotes that exact artifact after a
  successful `main` CI run; manual Pages dispatches run the same Aspect contract.

## Architecture guardrails

Hovel uses a hexagonal layering with dependencies pointing inward:

```
adapters -> app -> domain
infra    -> app -> domain
```

- `core/internal/domain` must not import CLI, TUI, REST, MCP, storage, RPC, or
  concrete module/service code. Keep it pure; construct value objects through
  their `New...` constructors so validation runs.
- Front ends call application services (`internal/app`); they do not reach into
  adapters directly.
- Match the surrounding code: error wrapping, and defensive copying of
  maps/slices at boundaries.

## Safety-sensitive code

Hovel is an authorized red-team emulation and defensive validation tool for
scoped, auditable assessments. Changes to the throw planning, confirmation,
guardrail, or audit-event path need extra care. Preserve:

- A throw cannot start without a persisted plan and a recorded confirmation.
- `--now` skips the typed prompt but still records an auditable confirmation
  noting the bypass.
- Modules tagged `dangerous` require `--allow-dangerous` before they can throw.
- Never silently redact or drop operator-controlled configuration values.

See `SECURITY.md` and `CONTRIBUTING.md` for the fuller picture.
