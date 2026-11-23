import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifactSchema, verifyBuildSnapshot, workerClaimSchema } from "./build-queue.js";
import { createHash } from "node:crypto";

const validArtifact = {
  sha256: "a".repeat(64),
  sizeBytes: 1024,
  contentType: "application/zip"
};

test("accepts artifact completion metadata but rejects caller-selected object keys", () => {
  assert.equal(buildArtifactSchema.safeParse(validArtifact).success, true);
  assert.equal(buildArtifactSchema.safeParse({ ...validArtifact, objectKey: "artifacts/attacker/selected.zip" }).success, false);
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

test("worker claim requires explicit supported architectures and ROM bases", () => {
  const claim = {
    workerId: "worker-eu-01",
    leaseSeconds: 180,
    architectures: ["arm64"],
    romBases: ["lineage", "crdroid"]
  };
  assert.equal(workerClaimSchema.safeParse(claim).success, true);
  assert.equal(workerClaimSchema.safeParse({ ...claim, architectures: [] }).success, false);
  assert.equal(workerClaimSchema.safeParse({ ...claim, romBases: ["evolution"] }).success, false);
  assert.equal(workerClaimSchema.safeParse({ ...claim, leaseSeconds: 10 }).success, false);
});
