import assert from "node:assert/strict";
import test from "node:test";
import { isSafeArtifactObjectKey } from "./artifact-storage.js";

test("accepts server-generated artifact object keys", () => {
  assert.equal(isSafeArtifactObjectKey("artifacts/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002/1/00000000-0000-4000-8000-000000000003.zip"), true);
});

test("rejects traversal, empty segments, and unsafe characters", () => {
  for (const key of [
    "../secret.zip",
    "artifacts/../secret.zip",
    "artifacts//job/file.zip",
    "artifacts/./job/file.zip",
    "artifacts/job/%2e%2e/file.zip",
    "artifacts/job/file.zip?public=true",
    "/artifacts/job/file.zip",
    "artifacts\\job\\file.zip"
  ]) assert.equal(isSafeArtifactObjectKey(key), false, key);
});

test("rejects undersized and oversized object keys", () => {
  assert.equal(isSafeArtifactObjectKey("ab"), false);
  assert.equal(isSafeArtifactObjectKey("a".repeat(513)), false);
});
