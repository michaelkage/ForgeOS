import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { z } from "zod";
import { config } from "./config.js";
import { pool, query } from "./db.js";
import { configSchema, deviceSchema, loginSchema, registerSchema } from "./schemas.js";
import { createSession, destroySession, hashPassword, loadSession, requireAdmin, requireCsrf, requireUser, verifyPassword } from "./security.js";
import { validateRepositoryManifest } from "./manifest.js";
import { deviceSourceSchema, verifyDeviceSource } from "./device-resolver.js";

const app = Fastify({ logger: true, trustProxy: config.TRUST_PROXY.length ? config.TRUST_PROXY : false, bodyLimit: 256 * 1024 });
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
});
await app.register(cookie);
await app.register(cors, { origin: config.WEB_ORIGIN, credentials: true, methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] });
await app.register(fastifyStatic, { root: fileURLToPath(new URL("../web", import.meta.url)), index: ["index.html"] });
await app.register(rateLimit, { max: 120, timeWindow: "1 minute" });
app.addHook("onRequest", async request => { await loadSession(request); });
app.addHook("onRequest", async (request, reply) => {
  const origin = request.headers.origin;
  if (origin && origin !== config.WEB_ORIGIN) await reply.code(403).send({ error: "origin_not_allowed" });
});
app.addHook("onSend", async (_request, reply, payload) => { reply.header("Cache-Control", "no-store"); return payload; });
const fail = (reply: any, status: number, error: string) => reply.code(status).send({ error });
const parse = <T>(schema: z.ZodType<T>, body: unknown) => schema.safeParse(body);

app.get("/healthz", async () => ({ ok: true, service: "forgeos-platform-api" }));
app.get("/readyz", async (_request, reply) => {
  try { await query("SELECT 1"); return { ok: true, database: "connected" }; }
  catch { return fail(reply, 503, "database_unavailable"); }
});

app.post("/api/auth/register", { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } }, async (request, reply) => {
  const parsed = parse(registerSchema, request.body);
  if (!parsed.success) return fail(reply, 400, "invalid_registration");
  try {
    const result = await query<{id:string;email:string;role:"user"|"admin"}>(
      "INSERT INTO forgeos_users(email,password_hash) VALUES($1,$2) RETURNING id,email,role",
      [parsed.data.email, await hashPassword(parsed.data.password)]
    );
    const user = result.rows[0]!, csrfToken = await createSession(user, reply);
    return reply.code(201).send({ user, csrfToken });
  } catch (error) {
    if ((error as {code?:string}).code === "23505") return fail(reply,409,"email_already_registered");
    request.log.error(error); return fail(reply,500,"registration_failed");
  }
});
app.post("/api/auth/login", { config: { rateLimit: { max: 10, timeWindow: "15 minutes" } } }, async (request, reply) => {
  const parsed = parse(loginSchema, request.body);
  if (!parsed.success) return fail(reply,400,"invalid_credentials");
  const result = await query<{id:string;email:string;role:"user"|"admin";password_hash:string}>(
    "SELECT id,email,role,password_hash FROM forgeos_users WHERE email=$1",[parsed.data.email]
  );
  const row = result.rows[0];
  if (!row || !(await verifyPassword(row.password_hash,parsed.data.password))) return fail(reply,401,"invalid_credentials");
  const user = {id:row.id,email:row.email,role:row.role}, csrfToken = await createSession(user,reply);
  return {user,csrfToken};
});
app.get("/api/auth/me", async (request,reply) => {
  if (!requireUser(request,reply)) return;
  return {user:request.user,csrfToken:request.csrfToken};
});
app.post("/api/auth/logout", async (request,reply) => {
  if (!requireUser(request,reply) || !requireCsrf(request,reply)) return;
  await destroySession(request,reply); return {ok:true};
});

app.get("/api/devices", async () => {
  const result = await query(
    `SELECT d.id,d.codename,d.manufacturer,d.model,d.chipset,d.architecture,
      COALESCE(jsonb_agg(jsonb_build_object('base',b.rom_base,'manifestPath',b.manifest_path,'branchName',b.branch_name))
      FILTER (WHERE b.enabled), '[]'::jsonb) AS rom_bases,
      (EXISTS (SELECT 1 FROM forgeos_device_rom_bases rb WHERE rb.device_id=d.id AND rb.enabled=true) AND NOT EXISTS (SELECT 1 FROM forgeos_device_rom_bases rb WHERE rb.device_id=d.id AND rb.enabled=true AND NOT EXISTS (SELECT 1 FROM forgeos_device_sources s WHERE s.device_id=d.id AND s.source_kind='device' AND s.rom_base=rb.rom_base AND s.verification_status='verified'))) AS device_tree_verified
      FROM forgeos_devices d LEFT JOIN forgeos_device_rom_bases b ON b.device_id=d.id AND b.enabled=true
      WHERE d.enabled=true GROUP BY d.id ORDER BY d.manufacturer,d.model`
  );
  return {devices:result.rows};
});

app.get("/api/admin/devices", async (request,reply) => {
  if (!requireAdmin(request,reply)) return;
  const result=await query(
    `SELECT d.id,d.codename,d.manufacturer,d.model,d.chipset,d.architecture,d.enabled,d.notes,
      COALESCE(jsonb_agg(jsonb_build_object('base',b.rom_base,'manifestPath',b.manifest_path,'branchName',b.branch_name,'enabled',b.enabled))
      FILTER (WHERE b.device_id IS NOT NULL), '[]'::jsonb) AS rom_bases
      FROM forgeos_devices d LEFT JOIN forgeos_device_rom_bases b ON b.device_id=d.id
      GROUP BY d.id ORDER BY d.manufacturer,d.model`
  );
  return {devices:result.rows};
});

app.get("/api/admin/devices/:id/sources", async (request,reply) => {
  if (!requireAdmin(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  if (!id.success) return fail(reply,400,"invalid_device_id");
  const result=await query(
    "SELECT id,source_kind,rom_base,repository_url,branch_name,source_path,verification_status,verified_commit_sha,verified_files,verification_error,last_checked_at FROM forgeos_device_sources WHERE device_id=$1 ORDER BY source_kind,rom_base,created_at",
    [id.data]
  );
  return {sources:result.rows};
});
app.post("/api/admin/devices/:id/sources", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  const parsed=deviceSourceSchema.safeParse(request.body);
  if (!id.success || !parsed.success) return fail(reply,400,"invalid_device_source");
  const source=parsed.data;
  const exists=source.romBase
    ? await query("SELECT d.id FROM forgeos_devices d JOIN forgeos_device_rom_bases b ON b.device_id=d.id WHERE d.id=$1 AND b.rom_base=$2 AND b.enabled=true",[id.data,source.romBase])
    : await query("SELECT id FROM forgeos_devices WHERE id=$1",[id.data]);
  if (!exists.rowCount) return fail(reply,404,"device_or_enabled_rom_base_not_found");
  const result=await query(
    "INSERT INTO forgeos_device_sources(device_id,source_kind,rom_base,repository_url,branch_name,source_path) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id,source_kind,rom_base,repository_url,branch_name,source_path) DO UPDATE SET verification_status='pending',verified_commit_sha=NULL,verified_files='[]'::jsonb,verification_error=NULL,last_checked_at=NULL,updated_at=now() RETURNING id",
    [id.data,source.sourceKind,source.romBase??null,source.repositoryUrl.replace(/\/+$/,""),source.branchName,source.sourcePath]
  );
  await query("UPDATE forgeos_devices SET enabled=false WHERE id=$1",[id.data]);
  return reply.code(201).send({sourceId:result.rows[0]!.id,status:"pending"});
});
app.post("/api/admin/devices/:id/sources/:sourceId/verify", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const params=request.params as {id?:string;sourceId?:string};
  const id=z.string().uuid().safeParse(params.id), sourceId=z.string().uuid().safeParse(params.sourceId);
  if (!id.success || !sourceId.success) return fail(reply,400,"invalid_source_id");
  const selected=await query(
    "SELECT source_kind,rom_base,repository_url,branch_name,source_path FROM forgeos_device_sources WHERE id=$1 AND device_id=$2",
    [sourceId.data,id.data]
  );
  const row=selected.rows[0] as {source_kind:"device"|"kernel"|"vendor";rom_base:"lineage"|"crdroid"|null;repository_url:string;branch_name:string;source_path:string}|undefined;
  if (!row) return fail(reply,404,"device_source_not_found");
  const verified=await verifyDeviceSource({
    sourceKind:row.source_kind,romBase:row.rom_base??undefined,repositoryUrl:row.repository_url,branchName:row.branch_name,sourcePath:row.source_path
  },config.GITHUB_TOKEN);
  await query(
    "UPDATE forgeos_device_sources SET verification_status=$3,verified_commit_sha=$4,verified_files=$5,verification_error=$6,last_checked_at=now(),updated_at=now() WHERE id=$1 AND device_id=$2",
    [sourceId.data,id.data,verified.status,verified.commitSha,JSON.stringify(verified.files),verified.error]
  );
  if (verified.status !== "verified" && row.source_kind === "device") {
    await query("UPDATE forgeos_devices SET enabled=false WHERE id=$1",[id.data]);
  }
  return {sourceId:sourceId.data,...verified};
});

app.post("/api/admin/devices", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const parsed = parse(deviceSchema,request.body);
  if (!parsed.success) return fail(reply,400,"invalid_device");
  const d=parsed.data;
  if (d.enabled) return fail(reply,422,"verify_device_source_before_activation");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const inserted=await client.query(
      "INSERT INTO forgeos_devices(codename,manufacturer,model,chipset,architecture,enabled,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id",
      [d.codename,d.manufacturer,d.model,d.chipset??null,d.architecture,d.enabled,d.notes??null]
    );
    const deviceId=inserted.rows[0].id as string;
    for (const b of d.romBases) await client.query(
      "INSERT INTO forgeos_device_rom_bases(device_id,rom_base,manifest_path,branch_name,enabled) VALUES($1,$2,$3,$4,$5)",
      [deviceId,b.base,b.manifestPath,b.branchName,b.enabled]
    );
    await client.query("COMMIT"); return reply.code(201).send({id:deviceId});
  } catch(error) {
    await client.query("ROLLBACK");
    if ((error as {code?:string}).code==="23505") return fail(reply,409,"device_codename_exists");
    request.log.error(error); return fail(reply,500,"device_create_failed");
  } finally { client.release(); }
});

app.put("/api/admin/devices/:id", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id), parsed=parse(deviceSchema,request.body);
  if (!id.success || !parsed.success) return fail(reply,400,"invalid_device");
  const d=parsed.data;
  if (d.enabled) {
    const enabledBases=d.romBases.filter(base=>base.enabled).map(base=>base.base);
    if (!enabledBases.length) return fail(reply,422,"at_least_one_enabled_rom_base_required");
    const missing=await query("SELECT requested.rom_base FROM unnest($2::forgeos_rom_base[]) AS requested(rom_base) WHERE NOT EXISTS (SELECT 1 FROM forgeos_device_sources s WHERE s.device_id=$1 AND s.source_kind='device' AND s.rom_base=requested.rom_base AND s.verification_status='verified') LIMIT 1",[id.data,enabledBases]);
    if (missing.rowCount) return fail(reply,422,"verify_all_device_tree_sources_before_activation");
  }
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const updated=await client.query(
      "UPDATE forgeos_devices SET codename=$2,manufacturer=$3,model=$4,chipset=$5,architecture=$6,enabled=$7,notes=$8 WHERE id=$1 RETURNING id",
      [id.data,d.codename,d.manufacturer,d.model,d.chipset??null,d.architecture,d.enabled,d.notes??null]
    );
    if (!updated.rowCount) { await client.query("ROLLBACK"); return fail(reply,404,"device_not_found"); }
    await client.query("UPDATE forgeos_device_rom_bases SET enabled=false WHERE device_id=$1",[id.data]);
    for (const b of d.romBases) await client.query(
      "INSERT INTO forgeos_device_rom_bases(device_id,rom_base,manifest_path,branch_name,enabled) VALUES($1,$2,$3,$4,$5) ON CONFLICT(device_id,rom_base) DO UPDATE SET manifest_path=EXCLUDED.manifest_path,branch_name=EXCLUDED.branch_name,enabled=EXCLUDED.enabled",
      [id.data,b.base,b.manifestPath,b.branchName,b.enabled]
    );
    await client.query("COMMIT"); return {ok:true};
  } catch(error) {
    await client.query("ROLLBACK");
    if ((error as {code?:string}).code==="23505") return fail(reply,409,"device_codename_exists");
    request.log.error(error); return fail(reply,500,"device_update_failed");
  } finally { client.release(); }
});

app.post("/api/admin/devices/:id/activate", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  if (!id.success) return fail(reply,400,"invalid_device_id");
  const result=await query(
    "UPDATE forgeos_devices d SET enabled=true WHERE d.id=$1 AND EXISTS (SELECT 1 FROM forgeos_device_rom_bases b WHERE b.device_id=d.id AND b.enabled=true) AND NOT EXISTS (SELECT 1 FROM forgeos_device_rom_bases b WHERE b.device_id=d.id AND b.enabled=true AND NOT EXISTS (SELECT 1 FROM forgeos_device_sources s WHERE s.device_id=d.id AND s.source_kind='device' AND s.rom_base=b.rom_base AND s.verification_status='verified')) RETURNING d.id",
    [id.data]
  );
  if (!result.rowCount) return fail(reply,422,"verified_device_source_and_rom_base_required");
  return {ok:true,enabled:true};
});

app.delete("/api/admin/devices/:id", async (request,reply) => {
  if (!requireAdmin(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  if (!id.success) return fail(reply,400,"invalid_device_id");
  const result=await query("UPDATE forgeos_devices SET enabled=false WHERE id=$1 RETURNING id",[id.data]);
  if (!result.rowCount) return fail(reply,404,"device_not_found");
  return {ok:true,disabled:true};
});

app.get("/api/configurations", async (request,reply) => {
  if (!requireUser(request,reply)) return;
  const result=await query(
    `SELECT c.id,c.name,c.rom_base,c.root_method,c.manifest_revision,c.options,c.status,c.validation_report,
      c.created_at,c.updated_at,d.codename,d.manufacturer,d.model
      FROM forgeos_rom_configurations c JOIN forgeos_devices d ON d.id=c.device_id
      WHERE c.user_id=$1 ORDER BY c.updated_at DESC`,[request.user!.id]
  );
  return {configurations:result.rows};
});
app.post("/api/configurations", async (request,reply) => {
  if (!requireUser(request,reply) || !requireCsrf(request,reply)) return;
  const parsed=parse(configSchema,request.body);
  if (!parsed.success) return fail(reply,400,"invalid_configuration");
  const c=parsed.data;
  const supported=await query<{manifest_path:string;branch_name:string}>(
    `SELECT b.manifest_path,b.branch_name FROM forgeos_devices d JOIN forgeos_device_rom_bases b ON b.device_id=d.id
      WHERE d.id=$1 AND d.enabled=true AND b.rom_base=$2 AND b.enabled=true`,[c.deviceId,c.romBase]
  );
  if (!supported.rowCount) return fail(reply,422,"device_or_rom_base_not_supported");
  const result=await query(
    "INSERT INTO forgeos_rom_configurations(user_id,device_id,name,rom_base,root_method,manifest_revision,options) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,status,created_at,updated_at",
    [request.user!.id,c.deviceId,c.name,c.romBase,c.rootMethod,c.manifestRevision??supported.rows[0]!.branch_name,c.options]
  );
  return reply.code(201).send({configuration:result.rows[0]});
});
app.get("/api/configurations/:id", async (request,reply) => {
  if (!requireUser(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  if (!id.success) return fail(reply,400,"invalid_configuration_id");
  const result=await query(
    `SELECT c.*,d.codename,d.manufacturer,d.model,b.manifest_path,b.branch_name
      FROM forgeos_rom_configurations c JOIN forgeos_devices d ON d.id=c.device_id
      JOIN forgeos_device_rom_bases b ON b.device_id=d.id AND b.rom_base=c.rom_base
      WHERE c.id=$1 AND c.user_id=$2`,[id.data,request.user!.id]
  );
  if (!result.rowCount) return fail(reply,404,"configuration_not_found");
  return {configuration:result.rows[0]};
});
app.put("/api/configurations/:id", async (request,reply) => {
  if (!requireUser(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id), parsed=parse(configSchema,request.body);
  if (!id.success || !parsed.success) return fail(reply,400,"invalid_configuration");
  const c=parsed.data;
  const supported=await query(
    "SELECT b.branch_name FROM forgeos_devices d JOIN forgeos_device_rom_bases b ON b.device_id=d.id WHERE d.id=$1 AND d.enabled=true AND b.rom_base=$2 AND b.enabled=true",
    [c.deviceId,c.romBase]
  );
  if (!supported.rowCount) return fail(reply,422,"device_or_rom_base_not_supported");
  const result=await query(
    "UPDATE forgeos_rom_configurations SET device_id=$3,name=$4,rom_base=$5,root_method=$6,manifest_revision=$7,options=$8,status='draft',validation_report=NULL WHERE id=$1 AND user_id=$2 RETURNING id,status,updated_at",
    [id.data,request.user!.id,c.deviceId,c.name,c.romBase,c.rootMethod,c.manifestRevision??supported.rows[0]!.branch_name,c.options]
  );
  if (!result.rowCount) return fail(reply,404,"configuration_not_found");
  return {configuration:result.rows[0]};
});
app.post("/api/configurations/:id/validate", async (request,reply) => {
  if (!requireUser(request,reply) || !requireCsrf(request,reply)) return;
  const id=z.string().uuid().safeParse((request.params as {id?:string}).id);
  if (!id.success) return fail(reply,400,"invalid_configuration_id");
  const result=await query(
    `SELECT c.rom_base,c.root_method,c.manifest_revision,d.enabled AS device_enabled,b.enabled AS base_enabled,
      b.manifest_path,b.branch_name,d.codename FROM forgeos_rom_configurations c
      JOIN forgeos_devices d ON d.id=c.device_id
      JOIN forgeos_device_rom_bases b ON b.device_id=d.id AND b.rom_base=c.rom_base
      WHERE c.id=$1 AND c.user_id=$2`,[id.data,request.user!.id]
  );
  const row=result.rows[0] as {rom_base:string;root_method:string;manifest_revision:string|null;device_enabled:boolean;base_enabled:boolean;manifest_path:string;branch_name:string;codename:string}|undefined;
  if (!row) return fail(reply,404,"configuration_not_found");
  const manifest=await validateRepositoryManifest(config.MANIFEST_ROOT,row.manifest_path);
  const errors=[...manifest.errors];
  if (!row.device_enabled) errors.push("Selected device is disabled");
  if (!row.base_enabled) errors.push("Selected ROM base is disabled for this device");
  if (row.manifest_revision && row.manifest_revision!==row.branch_name) errors.push("Manifest revision does not match the verified device/base branch");
  const warnings=["This validates configuration and manifest metadata only; it does not sync or compile Android source."];
  if (row.root_method!=="none") warnings.push("Selected root method is recorded only; root patching and boot image modification are not implemented.");
  const report={valid:errors.length===0,device:row.codename,romBase:row.rom_base,rootMethod:row.root_method,manifestPath:row.manifest_path,projectCount:manifest.projectCount,errors,warnings};
  await query("UPDATE forgeos_rom_configurations SET status=$3,validation_report=$4 WHERE id=$1 AND user_id=$2",[id.data,request.user!.id,report.valid?"validated":"draft",report]);
  return {report};
});
app.post("/api/configurations/:id/queue", async (request,reply) => {
  if (!requireUser(request,reply) || !requireCsrf(request,reply)) return;
  return fail(reply,503,"android_build_workers_not_configured");
});

app.setNotFoundHandler((_request,reply)=>reply.code(404).send({error:"not_found"}));
app.setErrorHandler((error,request,reply)=>{request.log.error(error);reply.code(500).send({error:"internal_server_error"});});
try { await app.listen({host:config.HOST,port:config.PORT}); }
catch(error) { app.log.error(error); await pool.end(); process.exit(1); }
for (const signal of ["SIGINT","SIGTERM"] as const) process.on(signal,async()=>{await app.close();await pool.end();process.exit(0);});
