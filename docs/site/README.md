# Hovel docs site

The handwritten documentation is plain HTML under `src/content/`. Astro owns
first-party HTML, navigation, version rendering, and the report application.
Bazel owns Node, pnpm, npm packages, generated SDK reference, demos, inputs,
and outputs. `//docs/tools/docs:site` assembles those declared artifacts into
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

Search is generated from fragment metadata and body text as
`search-index.json`, then loaded only when the search dialog opens. The home
fragment contains one `data-hovel-component="demo-carousel"` marker;
`src/components/DemoCarousel.astro` owns the reusable interaction and the
ordered slide data lives in `src/pages/index.astro`.

## Commands

| Command | Purpose |
| --- | --- |
| `task docs:check` | Build the hermetic Astro artifact and run docs tests. |
| `task docs:build` | Build declared Astro, SDK, and demo artifacts and materialize `_site/`. |
| `task docs:dev` | Run Astro through Bazel on `http://localhost:4321`. |
| `task docs:preview` | Serve the assembled `_site/` on `http://localhost:4322`. |
| `task docs:report` | Run report-producing tests and build `_site/` with their evidence. |
| `task docs:deps` | Refresh `pnpm-lock.yaml` with Bazel-managed pnpm. |

Do not run Node, pnpm, Astro, or Bazel directly. Do not edit `_site/`.

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
The SDK generator owns only the native Sphinx, pkgsite, and rustdoc interiors;
those tools retain their purpose-built reference navigation instead of copying
Hovel's site chrome.

## Hermetic boundary

`MODULE.bazel` pins `aspect_rules_js`, `rules_nodejs`, and Node. `package.json`
pins pnpm and Astro exactly, and `pnpm-lock.yaml` supplies integrity hashes for
the npm graph. Lifecycle scripts are disabled both in pnpm configuration and
`npm_translate_lock`. The Astro action runs with declared sources, including
root `VERSION`, and writes only its declared `dist` output directory. The final
site assembler consumes declared TreeArtifacts and files and rejects output
collisions. Native SDK reference generation remains an explicit local action:
pkgsite opens a loopback server and uv uses its managed package cache. The
published site itself does not load CDN resources.
