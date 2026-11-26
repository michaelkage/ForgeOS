import assert from "node:assert/strict";
import test from "node:test";
import { createBootstrapCredential, hashBootstrapCredential } from "./guest-bootstrap-credentials.js";

test("creates a high-entropy URL-safe credential and persists only its digest", () => {
  const first = createBootstrapCredential();
  const second = createBootstrapCredential();
  assert.match(first.credential, /^[A-Za-z0-9_-]{40,64}$/);
  assert.equal(first.credential.length, 43);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.sha256, hashBootstrapCredential(first.credential));
  assert.notEqual(first.credential, second.credential);
  assert.notEqual(first.sha256, second.sha256);
});

test("credential hashing is deterministic and does not expose the credential", () => {
  const credential = "A".repeat(43);
  const digest = hashBootstrapCredential(credential);
  assert.equal(digest.length, 64);
  assert.notEqual(digest, credential);
  assert.equal(digest, hashBootstrapCredential(credential));
});
