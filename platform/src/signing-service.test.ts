import assert from "node:assert/strict";
import test from "node:test";
import { signUploadedArtifact } from "./signing-service.js";

test("signing adapter rejects invalid job metadata before contacting storage or signer", async () => {
  await assert.rejects(
    signUploadedArtifact({
      userId: "not-a-uuid",
      jobId: "123e4567-e89b-42d3-a456-426614174000",
      attempt: 1,
      snapshotSha256: "a".repeat(64),
      inputObjectKey: "artifacts/user/job/1/file.zip",
      inputSha256: "b".repeat(64),
      inputSizeBytes: 1024
    }),
    /invalid signing request metadata/
  );
});

test("signing adapter rejects attempts outside the durable build retry policy", async () => {
  await assert.rejects(
    signUploadedArtifact({
      userId: "123e4567-e89b-42d3-a456-426614174001",
      jobId: "123e4567-e89b-42d3-a456-426614174000",
      attempt: 21,
      snapshotSha256: "a".repeat(64),
      inputObjectKey: "artifacts/user/job/1/file.zip",
      inputSha256: "b".repeat(64),
      inputSizeBytes: 1024
    }),
    /invalid signing request metadata/
  );
});
