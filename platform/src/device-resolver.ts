import { z } from "zod";

const validGitRef = (value: string) => /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/.test(value) && !value.includes("..") && !value.includes("//") && !value.includes("@{") && !value.endsWith("/") && !value.endsWith(".") && !value.split("/").some(part => part.endsWith(".lock"));

export const deviceSourceSchema = z.object({
  sourceKind: z.enum(["device", "kernel", "vendor"]),
  repositoryUrl: z.string().url().max(300).refine(value => {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.hostname === "github.com" &&
        !url.username && !url.password && !url.search && !url.hash &&
        /^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/.test(url.pathname);
    } catch { return false; }
  }, "Only public GitHub repository URLs are supported"),
  branchName: z.string().refine(validGitRef, "Invalid Git branch or tag name"),
  sourcePath: z.string().max(240).refine(value =>
    value === "" || (!value.startsWith("/") && !value.split("/").includes("..") && !/[\u0000-\u001f]/.test(value)),
    "Source path must be a safe repository-relative path"
  ).default("")
}).strict();

export type DeviceSourceInput = z.infer<typeof deviceSourceSchema>;
export type VerificationResult = { status: "verified" | "failed"; commitSha: string | null; files: string[]; error: string | null };
type GithubRepo = { archived?: boolean; disabled?: boolean };
type GithubBranch = { commit?: { sha?: string } };
type GithubContent = { name?: string; type?: string }[] | { message?: string };
const API = "https://api.github.com";

async function githubGet<T>(path: string, token?: string): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "ForgeOS-Device-Resolver"
  };
  if (token) headers.Authorization = "Bearer " + token;
  const response = await fetch(API + path, { headers, signal: AbortSignal.timeout(12000) });
  if (response.status === 404) throw new Error("Repository, branch, or source path was not found or is not public");
  if (response.status === 403 || response.status === 429) throw new Error("GitHub API rate limit or access restriction; configure GITHUB_TOKEN");
  if (!response.ok) throw new Error("GitHub API returned HTTP " + response.status);
  return await response.json() as T;
}

export async function verifyDeviceSource(input: DeviceSourceInput, token?: string): Promise<VerificationResult> {
  try {
    const url = new URL(input.repositoryUrl);
    const [owner, rawRepo] = url.pathname.replace(/\.git\/?$/, "").split("/").filter(Boolean);
    if (!owner || !rawRepo) throw new Error("Invalid GitHub repository URL");
    const prefix = "/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(rawRepo);
    const repo = await githubGet<GithubRepo>(prefix, token);
    if (repo.archived || repo.disabled) throw new Error("Repository is archived or disabled");
    const branch = await githubGet<GithubBranch>(prefix + "/branches/" + encodeURIComponent(input.branchName), token);
    const sha = branch.commit?.sha;
    if (!sha || !/^[a-f0-9]{40}$/i.test(sha)) throw new Error("GitHub returned no valid commit SHA");
    const sourcePath = input.sourcePath ? "/" + input.sourcePath.split("/").map(encodeURIComponent).join("/") : "";
    const listing = await githubGet<GithubContent>(prefix + "/contents" + sourcePath + "?ref=" + encodeURIComponent(input.branchName), token);
    if (!Array.isArray(listing)) throw new Error("Source path is not a directory");
    const files = listing.filter(item => item.type === "file" && typeof item.name === "string").map(item => item.name as string);
    if (input.sourceKind === "device") {
      const missing = ["AndroidProducts.mk", "BoardConfig.mk"].filter(name => !files.includes(name));
      if (missing.length) throw new Error("Device tree is missing: " + missing.join(", "));
      if (!["device.mk", "lineage_device.mk", "common.mk"].some(name => files.includes(name))) {
        throw new Error("Device tree requires device.mk, lineage_device.mk, or common.mk");
      }
    }
    if (input.sourceKind === "kernel" && (!files.includes("Makefile") || !files.includes("Kconfig"))) {
      throw new Error("Kernel root requires Makefile and Kconfig");
    }
    if (input.sourceKind === "vendor" && files.length === 0) throw new Error("Vendor source directory is empty");
    return { status: "verified", commitSha: sha, files: files.slice(0, 200), error: null };
  } catch (error) {
    return { status: "failed", commitSha: null, files: [], error: error instanceof Error ? error.message.slice(0, 500) : "Verification failed" };
  }
}
