import assert from "node:assert/strict";
import { test } from "node:test";
import { configSchema, deviceSchema } from "./schemas.js";

const device = {
  codename: "example",
  manufacturer: "Example",
  model: "Example Phone",
  architecture: "arm64",
  enabled: false,
  romBases: [{ base: "lineage", manifestPath: "default.xml", branchName: "lineage-24.0", enabled: true }]
};

test("device profiles require unique ROM bases and matching manifest files", () => {
  assert.equal(deviceSchema.safeParse(device).success, true);
  assert.equal(deviceSchema.safeParse({ ...device, romBases: [] }).success, false);
  assert.equal(deviceSchema.safeParse({ ...device, romBases: [{ ...device.romBases[0], manifestPath: "snippets/crdroid.xml" }] }).success, false);
  assert.equal(deviceSchema.safeParse({ ...device, romBases: [{ ...device.romBases[0], branchName: "../../unsafe" }] }).success, false);
  assert.equal(deviceSchema.safeParse({ ...device, romBases: [...device.romBases, { base: "lineage", manifestPath: "default.xml", branchName: "lineage-24.0", enabled: true }] }).success, false);
});

test("ROM configuration rejects incompatible Google apps combinations and unsafe refs", () => {
  const valid = {
    name: "Daily driver",
    deviceId: "00000000-0000-4000-8000-000000000001",
    romBase: "lineage",
    rootMethod: "none",
    manifestRevision: "lineage-24.0",
    options: { includeGapps: false, includeMicroG: false, debloatPackages: ["com.example.app"], featureFlags: {} }
  };
  assert.equal(configSchema.safeParse(valid).success, true);
  assert.equal(configSchema.safeParse({ ...valid, options: { ...valid.options, includeGapps: true, includeMicroG: true } }).success, false);
  assert.equal(configSchema.safeParse({ ...valid, manifestRevision: "../../unsafe" }).success, false);
  assert.equal(configSchema.safeParse({ ...valid, options: { ...valid.options, debloatPackages: ["../../system"] } }).success, false);
});
