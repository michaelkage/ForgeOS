import { z } from "zod";

const validGitRef = (value: string) => /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/.test(value) && !value.includes("..") && !value.includes("//") && !value.includes("@{") && !value.endsWith("/") && !value.endsWith(".") && !value.split("/").some(part => part.endsWith(".lock"));

export const registerSchema = z.object({
  email: z.string().email().max(254).transform(v => v.toLowerCase()),
  password: z.string().min(12).max(128)
});
export const loginSchema = z.object({
  email: z.string().email().max(254).transform(v => v.toLowerCase()),
  password: z.string().min(1).max(128)
});
export const deviceSchema = z.object({
  codename: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,63}$/),
  manufacturer: z.string().trim().min(1).max(80),
  model: z.string().trim().min(1).max(120),
  chipset: z.string().trim().max(120).nullable().optional(),
  architecture: z.enum(["arm64", "arm", "x86_64"]).default("arm64"),
  enabled: z.boolean().default(false),
  notes: z.string().max(2000).nullable().optional(),
  romBases: z.array(z.object({
    base: z.enum(["lineage", "crdroid"]),
    manifestPath: z.enum(["default.xml", "snippets/crdroid.xml"]),
    branchName: z.string().refine(validGitRef, "Invalid Git branch or tag name"),
    enabled: z.boolean().default(true)
  })).max(2).superRefine((bases, ctx) => {
    for (const base of bases) {
      const expected = base.base === "lineage" ? "default.xml" : "snippets/crdroid.xml";
      if (base.manifestPath !== expected) ctx.addIssue({ code: "custom", message: "Manifest path does not match ROM base", path: [bases.indexOf(base), "manifestPath"] });
    }
    if (new Set(bases.map(base => base.base)).size !== bases.length) ctx.addIssue({ code: "custom", message: "ROM base entries must be unique" });
  }).refine((bases) => bases.length > 0, { message: "At least one supported ROM base is required" })
});
export const configSchema = z.object({
  name: z.string().trim().min(1).max(80),
  deviceId: z.string().uuid(),
  romBase: z.enum(["lineage", "crdroid"]),
  rootMethod: z.enum(["none", "magisk", "kernelsu", "apatch"]).default("none"),
  manifestRevision: z.string().trim().min(1).max(100).refine(validGitRef, "Invalid manifest revision").nullable().optional(),
  options: z.object({
    includeGapps: z.boolean().default(false),
    includeMicroG: z.boolean().default(false),
    debloatPackages: z.array(z.string().regex(/^[A-Za-z0-9_.]+$/)).max(100).default([]),
    featureFlags: z.record(z.boolean()).default({})
  }).strict().default({})
}).strict().superRefine((configuration, ctx) => {
  if (configuration.options.includeGapps && configuration.options.includeMicroG) {
    ctx.addIssue({ code: "custom", message: "Google apps and microG cannot both be selected", path: ["options"] });
  }
});
