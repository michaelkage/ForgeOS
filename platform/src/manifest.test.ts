import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { validateRepositoryManifest } from "./manifest.js";

test("validates and fingerprints exact manifest bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "forgeos-manifest-"));
  try {
    const xml = '<manifest><remote name="origin" fetch="https://github.com/" /><project name="LineageOS/android" path="frameworks/base" /></manifest>';
    await writeFile(join(root, "default.xml"), xml);
    const result = await validateRepositoryManifest(root, "default.xml");
    assert.equal(result.ok, true);
    assert.equal(result.content, xml);
    assert.equal(result.sha256, createHash("sha256").update(xml).digest("hex"));
    assert.equal(result.projectCount, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects duplicate and unsafe manifest project paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "forgeos-manifest-"));
  try {
    const xml = '<manifest><project name="a" path="frameworks/base" /><project name="b" path="frameworks/base" /><project name="c" path="../secrets" /></manifest>';
    await writeFile(join(root, "default.xml"), xml);
    const result = await validateRepositoryManifest(root, "default.xml");
    assert.equal(result.ok, false);
    assert.equal(result.content, null);
    assert.match(result.errors.join(" "), /Duplicate project path/);
    assert.match(result.errors.join(" "), /unsafe or missing path/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects manifest paths outside the repository allowlist", async () => {
  const result = await validateRepositoryManifest("/tmp", "../secrets.xml");
  assert.equal(result.ok, false);
  assert.equal(result.sha256, null);
});
