import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifactSchema, verifyBuildSnapshot } from "./build-queue.js";
import { createHash } from "node:crypto";

const validArtifact = {
  objectKey: "builds/2026/11/job-123/rom.zip",
  sha256: "a".repeat(64),
  sizeBytes: 1024,
  contentType: "application/zip"
};

test("accepts private artifact object metadata with a safe object key", () => {
  assert.equal(buildArtifactSchema.safeParse(validArtifact).success, true);
});

test("rejects traversal, absolute, empty-segment, and whitespace object keys", () => {
  for (const objectKey of [
    "../rom.zip",
    "builds/../rom.zip",
    "/builds/rom.zip",
    "builds//rom.zip",
    "builds/rom file.zip",
    "builds\\rom.zip",
    "builds/./rom.zip"
  ]) {
    assert.equal(buildArtifactSchema.safeParse({ ...validArtifact, objectKey }).success, false, objectKey);
  }
});

test("rejects invalid digest, zero-byte artifact, and non-ZIP content", () => {
  assert.equal(buildArtifactSchema.safeParse({ ...validArtifact, sha256: "bad" }).success, false);
  assert.equal(buildArtifactSchema.safeParse({ ...validArtifact, sizeBytes: 0 }).success, false);
  assert.equal(buildArtifactSchema.safeParse({ ...validArtifact, contentType: "application/octet-stream" }).success, false);
});

test("verifies canonical snapshot fingerprints independent of object key order", () => {
  const first = { device: { codename: "oriole", architecture: "arm64" }, schemaVersion: 1 };
  const reordered = { schemaVersion: 1, device: { architecture: "arm64", codename: "oriole" } };
  const canonical = '{"device":{"architecture":"arm64","codename":"oriole"},"schemaVersion":1}';
  const digest = createHash("sha256").update(canonical).digest("hex");
  assert.equal(verifyBuildSnapshot(first, digest), true);
  assert.equal(verifyBuildSnapshot(reordered, digest), true);
  assert.equal(verifyBuildSnapshot(reordered, "0".repeat(64)), false);
});
