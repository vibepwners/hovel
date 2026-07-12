import type { APIRoute } from "astro";
import { apiReferences } from "../lib/apiReferences";
import { htmlToText, pages } from "../lib/catalog";

const contentDocuments = pages.map((page) => ({
  description: page.description ?? "",
  group: page.area === "home" ? "Home" : page.group,
  href: page.href,
  text: htmlToText(page.body),
  title: page.navTitle ?? page.title,
}));

const apiDocuments = [
  {
    description: "Generated SDK reference for Python, Go, and Rust.",
    group: "API Docs",
    href: "api/sdk/index.html",
    text: apiReferences.map((reference) => `${reference.title} ${reference.subtitle}`).join(" "),
    title: "SDK API Reference",
  },
  {
    description: "Generated Go SDK package reference.",
    group: "API Docs",
    href: "api/sdk/go/index.html",
    text: apiReferences.filter((reference) => reference.language === "Go").map((reference) => reference.subtitle).join(" "),
    title: "Go SDK API",
  },
  ...apiReferences.map((reference) => ({
    description: reference.description,
    group: `${reference.language} API`,
    href: reference.href,
    text: reference.subtitle,
    title: reference.title,
  })),
];

const searchIndex = [...contentDocuments, ...apiDocuments];

export const GET: APIRoute = () => new Response(JSON.stringify(searchIndex), {
  headers: {
    "Content-Type": "application/json; charset=utf-8",
  },
});
