# Hovel docs site

The handwritten documentation is plain HTML under `src/content/`. Astro owns
first-party HTML, navigation, version rendering, and the report application.
Bazel owns Node, pnpm, npm packages, generated SDK reference, inputs, and
outputs. Demo GIFs are immutable checked-in inputs under
`public/assets/demos/`. `//docs/tools/docs:site` assembles those artifacts into
the complete site TreeArtifact; `//docs/tools/docs:stage_site` only materializes
that tree to root `_site/`.

## Author a page

Create an `.html` file under `src/content/`. Its relative path is its published
path. Start the file with the metadata contract and then write an HTML fragment:

```html
<!-- hovel-doc: {"title":"Provider lifecycle","group":"Runtime Platform","order":125} -->
<article>
  <h1>Provider lifecycle</h1>
  <p>Normal HTML goes here.</p>
</article>
```

The catalogue in `src/lib/catalog.ts` discovers all fragments. It rejects
missing metadata, duplicate ordering, complete HTML documents, and copied site
chrome. `src/components/Sidebar.astro` and `src/layouts/DocsLayout.astro` render
navigation from that catalogue.

Book organization is generated from metadata. The allowed parts are
`Foundations`, `Runtime Platform`, `Operator Experience`, `Module Development`,
`Engineering`, and `Reference`; `Contents` is reserved for the book index.
Chapter numbers, section numbers, contents rows, sidebar labels, browser titles,
and previous/next labels are all derived. Authors set only the part and a unique
order within it.

Module documentation uses the same generated structure. Put a module overview
at `src/content/modules/<module>/index.html`; its metadata additionally declares
`moduleOrder`, `moduleType`, `moduleStatus`, and `description`. Every other page
with the same `group` joins that module's document set. Astro derives `MM.DD`
numbers, the module directory, the cross-module switcher, the module sidebar,
section numbering, browser titles, and previous/next navigation.

Page-specific browser JavaScript can be inline in the fragment. Shared scripts,
CSS, images, downloads, and other static files go under `public/`, preserving
their path below the site root. Astro components are reserved for shared site
structure; content authors should not need Astro syntax.

The daemon OpenAPI document is the exception to direct `public/` authoring.
Edit the single canonical source at
`spec/reference/daemon-rpc.openapi.json`; the Bazel `daemon_rpc_openapi` target
publishes it as `public/spec/reference/daemon-rpc.openapi.json` for Astro. Never
restore a second checked-in copy under `public/`.

Search is generated from fragment metadata and body text as
`search-index.json`, then loaded only when the search dialog opens. The home
fragment contains one `data-hovel-component="demo-carousel"` marker;
`src/components/DemoCarousel.astro` owns the reusable interaction and the
ordered slide data lives in `src/pages/index.astro`.

## Commands

| Command | Purpose |
| --- | --- |
| `task docs:check` | Test, assemble, and link-check the complete remote-compatible site. |
| `task docs:build` | Build the declared site from checked-in assets and materialize `_site/`. |
| `task docs:demos` | Host-only: regenerate standard/UI demos and refresh checked-in GIFs. |
| `task docs:demos:wine` | Host-only: regenerate and refresh the Squatter Wine GIF. |
| `task docs:demos:all` | Host-only: regenerate and refresh every checked-in demo GIF. |
| `task docs:dev` | Run Astro through Bazel on `http://localhost:4321`. |
| `task docs:preview` | Serve the assembled `_site/` on `http://localhost:4322`. |
| `task docs:report` | Run report-producing tests and build `_site/` with their evidence. |
| `task docs:deps` | Refresh the pnpm and hashed Sphinx locks with Bazel-managed tools. |

Do not run Node, pnpm, Astro, or Bazel directly. Do not edit `_site/`.

## Refresh demo assets

Normal docs builds never invoke VHS, Chrome, tmux, or Docker. They consume the
checked-in GIFs under `public/assets/demos/`, which makes site assembly and link
validation eligible for sandboxed and remote execution.

When a tape or the UI changes, run the narrowest `task docs:demos...`
command above on a host with the required services. The Task-backed materializer
renders the selected Bazel demo targets, checks their durations, and replaces
the corresponding checked-in GIFs. Review those binary changes, then run
`task docs:check`; missing or stale links fail while assembling the site.

Astro always builds `reports/tests/latest/index.html`, its styles, and its
JavaScript, so navigation is valid in every artifact. Bazel test evidence is
necessarily post-test data: `task test:report` writes JSON, logs, and XML to
`.test-report/evidence/`; the explicit report materializer attaches that evidence
without replacing Astro HTML. Use `task docs:report` for the complete
test-to-published-site workflow. A normal `task docs:build` is deterministic and
always publishes the report status page without ambient workspace evidence.

On CI, `task docs:report` produces the evidence-backed `_site/` tree before the
`docs-site` artifact is uploaded. The Pages workflow promotes that exact
artifact after the full CI workflow succeeds on `main`; it does not rerun the
test suite. A manual Pages dispatch runs `task docs:report` before upload.

Astro also owns `api/sdk/index.html` and `api/sdk/go/index.html`. Their card
metadata is centralized in `src/lib/apiReferences.ts` and shared with search.
The SDK generator owns only the Sphinx, Go, and rustdoc interiors; those tools
retain their purpose-built reference navigation instead of copying Hovel's site
chrome.

## Hermetic boundary

`MODULE.bazel` pins `aspect_rules_js`, `rules_nodejs`, and Node. `package.json`
pins pnpm and Astro exactly, and `pnpm-lock.yaml` supplies integrity hashes for
the npm graph. Lifecycle scripts are disabled both in pnpm configuration and
`npm_translate_lock`. The Astro action runs with declared sources, including
root `VERSION`, and writes only its declared `dist` output directory. The final
site assembler consumes declared TreeArtifacts and checked-in public assets,
rejecting output collisions. Native SDK reference generation is also a declared
Bazel action:
Sphinx and its hashed dependency graph come from `rules_python`, the Go
reference renderer is a Bazel-built binary over the declared SDK sources, and
rustdoc comes from the registered Rust toolchain. The SDK and assembly actions
inherit no host shell environment, open no network service, and are eligible for
sandboxed and remote execution. The published site itself does not load CDN
resources.
