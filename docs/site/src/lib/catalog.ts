export type DocArea = "home" | "book" | "modules";

export interface DocMetadata {
  title: string;
  order: number;
  group: string;
  navTitle?: string;
  description?: string;
  moduleOrder?: number;
  moduleStatus?: string;
  moduleType?: string;
}

export interface DocPage extends DocMetadata {
  area: DocArea;
  body: string;
  href: string;
  slug: string;
  sourcePath: string;
  summary: string;
}

export interface NavGroup {
  label: string;
  pages: DocPage[];
}

export interface BookChapter {
  label: string;
  number: number;
  page: DocPage;
  partLabel: string;
  partNumber: number;
}

export interface BookPart {
  label: string;
  number: number;
  chapters: BookChapter[];
}

export interface ModuleDocument {
  label: string;
  number: number;
  page: DocPage;
}

export interface ModuleSpace {
  description: string;
  documents: ModuleDocument[];
  id: string;
  label: string;
  number: number;
  order: number;
  overview: DocPage;
  status: string;
  type: string;
}

const HEADER = "<!-- hovel-doc:";
const HTML_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&gt;": ">",
  "&lt;": "<",
  "&nbsp;": " ",
  "&quot;": '"',
  "&#39;": "'",
};
const rawPages = import.meta.glob<string>("../content/**/*.html", {
  eager: true,
  import: "default",
  query: "?raw",
});

function fail(sourcePath: string, message: string): never {
  throw new Error(`${sourcePath}: ${message}`);
}

export function htmlToText(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(amp|gt|lt|nbsp|quot|#39);/g, (entity) => HTML_ENTITIES[entity] ?? entity)
    .replace(/\s+/g, " ")
    .trim();
}

function summarize(body: string): string {
  const paragraphs = body.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi);
  for (const paragraph of paragraphs) {
    const text = htmlToText(paragraph[1]);
    if (text.length >= 48) return truncateSummary(text);
  }
  return truncateSummary(htmlToText(body));
}

function truncateSummary(text: string): string {
  if (text.length <= 220) return text;
  const shortened = text.slice(0, 217);
  const lastSpace = shortened.lastIndexOf(" ");
  return `${shortened.slice(0, lastSpace > 160 ? lastSpace : 217)}…`;
}

function parsePage(sourcePath: string, raw: string): DocPage {
  const start = raw.search(/\S/);
  const source = start < 0 ? "" : raw.slice(start);
  if (!source.startsWith(HEADER)) {
    fail(sourcePath, `first non-whitespace content must be ${HEADER} {...} -->`);
  }

  const headerEnd = source.indexOf("-->", HEADER.length);
  if (headerEnd < 0) {
    fail(sourcePath, "metadata comment is not closed");
  }

  let metadata: unknown;
  try {
    metadata = JSON.parse(source.slice(HEADER.length, headerEnd).trim());
  } catch (error) {
    fail(sourcePath, `invalid metadata JSON: ${String(error)}`);
  }
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    fail(sourcePath, "metadata must be a JSON object");
  }

  const candidate = metadata as Partial<DocMetadata>;
  if (typeof candidate.title !== "string" || candidate.title.trim() === "") {
    fail(sourcePath, "metadata.title must be a non-empty string");
  }
  if (!Number.isInteger(candidate.order) || (candidate.order ?? -1) < 0) {
    fail(sourcePath, "metadata.order must be a non-negative integer");
  }
  if (typeof candidate.group !== "string" || candidate.group.trim() === "") {
    fail(sourcePath, "metadata.group must be a non-empty string");
  }
  if (candidate.navTitle !== undefined && typeof candidate.navTitle !== "string") {
    fail(sourcePath, "metadata.navTitle must be a string when present");
  }
  if (candidate.description !== undefined && typeof candidate.description !== "string") {
    fail(sourcePath, "metadata.description must be a string when present");
  }
  if (candidate.moduleOrder !== undefined && (!Number.isInteger(candidate.moduleOrder) || candidate.moduleOrder < 0)) {
    fail(sourcePath, "metadata.moduleOrder must be a non-negative integer when present");
  }
  for (const field of ["moduleStatus", "moduleType"] as const) {
    if (candidate[field] !== undefined && (typeof candidate[field] !== "string" || candidate[field].trim() === "")) {
      fail(sourcePath, `metadata.${field} must be a non-empty string when present`);
    }
  }

  const body = source
    .slice(headerEnd + 3)
    .trim()
    .replaceAll("{{HOVEL_RELEASE_TAG}}", __HOVEL_RELEASE_TAG__)
    .replaceAll("{{HOVEL_VERSION}}", __HOVEL_VERSION__);
  if (!/<h1(?:\s|>)/i.test(body)) {
    fail(sourcePath, "content must contain an h1");
  }
  for (const forbidden of ["<html", "<head", "<body", "class=\"topbar\"", "class=\"sidebar\""]) {
    if (body.toLowerCase().includes(forbidden.toLowerCase())) {
      fail(sourcePath, `content fragment contains generated chrome: ${forbidden}`);
    }
  }

  const relative = sourcePath.replace(/^\.\.\/content\//, "").replace(/\.html$/, "");
  const slug = relative === "index" ? "index" : relative;
  const area: DocArea = slug === "index" ? "home" : slug.startsWith("spec/") ? "book" : "modules";

  return {
    area,
    body,
    description: candidate.description,
    group: candidate.group,
    href: slug === "index" ? "index.html" : `${slug}.html`,
    moduleOrder: candidate.moduleOrder,
    moduleStatus: candidate.moduleStatus,
    moduleType: candidate.moduleType,
    navTitle: candidate.navTitle,
    order: candidate.order as number,
    slug,
    sourcePath,
    summary: candidate.description ?? summarize(body),
    title: candidate.title,
  };
}

function comparePages(left: DocPage, right: DocPage): number {
  return left.order - right.order || left.title.localeCompare(right.title);
}

export const pages = Object.entries(rawPages).map(([path, raw]) => parsePage(path, raw));
const pageBySlug = new Map(pages.map((page) => [page.slug, page]));
if (pageBySlug.size !== pages.length) {
  throw new Error("docs content contains duplicate output slugs");
}
if (!pageBySlug.has("index")) {
  throw new Error("docs content must define src/content/index.html");
}

for (const area of ["book", "modules"] as const) {
  const keys = new Set<string>();
  for (const page of pages.filter((candidate) => candidate.area === area)) {
    const key = `${page.group}\u0000${page.order}`;
    if (keys.has(key)) {
      throw new Error(`${page.sourcePath}: duplicate order ${page.order} in group ${page.group}`);
    }
    keys.add(key);
  }
}

export function getPage(slug: string): DocPage {
  const page = pageBySlug.get(slug);
  if (!page) {
    throw new Error(`unknown docs page: ${slug}`);
  }
  return page;
}

const BOOK_GROUPS = [
  "Contents",
  "Foundations",
  "Runtime Platform",
  "Operator Experience",
  "Module Development",
  "Engineering",
  "Reference",
];
const MODULE_ROOT_GROUP = "Modules";
for (const page of pages.filter((candidate) => candidate.area === "book")) {
  if (!BOOK_GROUPS.includes(page.group)) {
    throw new Error(`${page.sourcePath}: unknown book group ${page.group}`);
  }
}

export function navGroups(area: Exclude<DocArea, "home">): NavGroup[] {
  const grouped = new Map<string, DocPage[]>();
  for (const page of pages.filter((candidate) => candidate.area === area)) {
    const existing = grouped.get(page.group) ?? [];
    existing.push(page);
    grouped.set(page.group, existing);
  }

  const labels = [...grouped.keys()].sort((left, right) => {
    if (area === "book") {
      return BOOK_GROUPS.indexOf(left) - BOOK_GROUPS.indexOf(right);
    }
    if (left === MODULE_ROOT_GROUP) return -1;
    if (right === MODULE_ROOT_GROUP) return 1;
    const order = new Map(moduleSpaces().map((module) => [module.id, module.order]));
    return (order.get(left) ?? Number.MAX_SAFE_INTEGER) - (order.get(right) ?? Number.MAX_SAFE_INTEGER)
      || left.localeCompare(right);
  });
  return labels.map((label) => ({ label, pages: grouped.get(label)!.sort(comparePages) }));
}

export function orderedPages(area: Exclude<DocArea, "home">): DocPage[] {
  return navGroups(area).flatMap((group) => group.pages);
}

export function bookParts(): BookPart[] {
  let chapterNumber = 0;
  return navGroups("book")
    .filter((group) => group.label !== "Contents")
    .map((group, partIndex) => {
      const partNumber = partIndex + 1;
      return {
        chapters: group.pages.map((page) => {
          chapterNumber += 1;
          return {
            label: String(chapterNumber).padStart(2, "0"),
            number: chapterNumber,
            page,
            partLabel: group.label,
            partNumber,
          };
        }),
        label: group.label,
        number: partNumber,
      };
    });
}

const chapterBySlug = new Map(bookParts().flatMap((part) => part.chapters).map((chapter) => [chapter.page.slug, chapter]));

export function bookChapter(page: DocPage): BookChapter | undefined {
  return chapterBySlug.get(page.slug);
}

const moduleSpaceList = buildModuleSpaces();
const moduleDocumentBySlug = new Map(
  moduleSpaceList.flatMap((module) => module.documents.map((document) => [document.page.slug, { document, module }] as const)),
);

function buildModuleSpaces(): ModuleSpace[] {
  const grouped = new Map<string, DocPage[]>();
  for (const page of pages.filter((candidate) => candidate.area === "modules" && candidate.group !== MODULE_ROOT_GROUP)) {
    const segments = page.slug.split("/");
    if (segments.length < 3 || segments[0] !== "modules" || segments[1] !== page.group) {
      fail(page.sourcePath, `module group ${page.group} must match its modules/<module>/ path`);
    }
    grouped.set(page.group, [...(grouped.get(page.group) ?? []), page]);
  }

  const orders = new Set<number>();
  const modules = [...grouped.entries()].map(([id, modulePages]) => {
    const overview = modulePages.find((page) => page.slug === `modules/${id}/index`);
    if (!overview) throw new Error(`module ${id} is missing modules/${id}/index.html`);
    if (overview.moduleOrder === undefined || overview.moduleType === undefined || overview.moduleStatus === undefined) {
      fail(overview.sourcePath, "module overview metadata requires moduleOrder, moduleType, and moduleStatus");
    }
    if (!overview.description) {
      fail(overview.sourcePath, "module overview metadata requires description");
    }
    if (orders.has(overview.moduleOrder)) {
      fail(overview.sourcePath, `duplicate moduleOrder ${overview.moduleOrder}`);
    }
    orders.add(overview.moduleOrder);
    return {
      description: overview.description,
      id,
      label: overview.title,
      order: overview.moduleOrder,
      overview,
      pages: modulePages.sort(comparePages),
      status: overview.moduleStatus,
      type: overview.moduleType,
    };
  }).sort((left, right) => left.order - right.order || left.label.localeCompare(right.label));

  return modules.map((module, moduleIndex) => ({
    description: module.description,
    documents: module.pages.map((page, pageIndex) => ({
      label: `${String(moduleIndex + 1).padStart(2, "0")}.${String(pageIndex + 1).padStart(2, "0")}`,
      number: pageIndex + 1,
      page,
    })),
    id: module.id,
    label: module.label,
    number: moduleIndex + 1,
    order: module.order,
    overview: module.overview,
    status: module.status,
    type: module.type,
  }));
}

export function moduleSpaces(): ModuleSpace[] {
  return moduleSpaceList;
}

export function moduleDocument(page: DocPage): { document: ModuleDocument; module: ModuleSpace } | undefined {
  return moduleDocumentBySlug.get(page.slug);
}

export function rootPrefix(slug: string): string {
  if (slug === "index") return "";
  return "../".repeat(slug.split("/").length - 1);
}
