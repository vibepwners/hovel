export interface ApiReference {
  description: string;
  href: string;
  language: "Go" | "Python" | "Rust";
  subtitle: string;
  title: string;
}

export const apiReferences: ApiReference[] = [
  {
    description: "Sphinx autodoc output from the importable Python SDK package.",
    href: "api/sdk/python/index.html",
    language: "Python",
    subtitle: "hovel_sdk",
    title: "Python SDK API",
  },
  {
    description: "pkgsite snapshot for the primary Go SDK package.",
    href: "api/sdk/go/hovel/index.html",
    language: "Go",
    subtitle: "github.com/Vibe-Pwners/hovel/sdk/go/hovel",
    title: "Go SDK API: hovel",
  },
  {
    description: "pkgsite snapshot for Go SDK test helpers.",
    href: "api/sdk/go/hoveltest/index.html",
    language: "Go",
    subtitle: "github.com/Vibe-Pwners/hovel/sdk/go/hoveltest",
    title: "Go SDK API: hoveltest",
  },
  {
    description: "rustdoc output from the Rust SDK crate root.",
    href: "api/sdk/rust/hovel/index.html",
    language: "Rust",
    subtitle: "crate hovel",
    title: "Rust SDK API",
  },
];
