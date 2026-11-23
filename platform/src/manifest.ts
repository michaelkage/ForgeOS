import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, relative, isAbsolute } from "node:path";
import { XMLParser, XMLValidator } from "fast-xml-parser";

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", allowBooleanAttributes: true });
const allowed = new Set(["default.xml", "snippets/crdroid.xml"]);
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

export async function validateRepositoryManifest(manifestRoot: string, manifestPath: string) {
  const errors: string[] = [];
  if (!allowed.has(manifestPath)) {
    return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["Manifest path is not in the platform allowlist"] };
  }
  const root = resolve(manifestRoot), target = resolve(root, manifestPath), rel = relative(root, target);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["Manifest path escapes the manifest root"] };
  }
  try {
    const buffer = await readFile(target);
    if (buffer.byteLength > MAX_MANIFEST_BYTES) {
      return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["Manifest exceeds the 2 MiB validation limit"] };
    }
    const xml = buffer.toString("utf8"), syntax = XMLValidator.validate(xml);
    if (syntax !== true) {
      return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["Manifest XML is malformed"] };
    }
    const document = parser.parse(xml) as { manifest?: { project?: unknown } };
    if (!document.manifest) {
      return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["XML root must be <manifest>"] };
    }
    const raw = document.manifest.project, projects = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
    const paths = new Set<string>();
    for (const item of projects) {
      const projectPath = (item as Record<string, unknown>)["@path"];
      if (typeof projectPath !== "string" || !projectPath || projectPath.startsWith("/") || projectPath.split("/").includes("..")) {
        errors.push("Manifest contains a project with an unsafe or missing path");
        continue;
      }
      if (paths.has(projectPath)) errors.push("Duplicate project path: " + projectPath);
      paths.add(projectPath);
    }
    return {
      ok: errors.length === 0,
      manifestPath,
      projectCount: projects.length,
      sha256: createHash("sha256").update(buffer).digest("hex"),
      content: errors.length === 0 ? xml : null,
      errors
    };
  } catch {
    return { ok: false, manifestPath, projectCount: 0, sha256: null, content: null, errors: ["Manifest file could not be read from the configured manifest root"] };
  }
}
