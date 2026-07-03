import { createClient } from "jsr:@supabase/supabase-js@2";

const PW = Deno.env.get("DASHBOARD_PASSWORD") || "";
const SB_URL = Deno.env.get("SUPABASE_URL") || "";
const SRK = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

// CORS is scoped to the known app origins instead of "*" (defense-in-depth).
// Unknown origins get the primary origin echoed, so a foreign browser page can't read responses.
const ALLOWED_ORIGINS = new Set([
  "https://yb471.github.io",
  "https://pjuwipjyxzxlmhebzdct.supabase.co",
]);
const PRIMARY_ORIGIN = "https://yb471.github.io";

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") || "";
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : PRIMARY_ORIGIN;
  return {
    "access-control-allow-origin": allow,
    "vary": "Origin",
    "access-control-allow-headers": "authorization, x-client-info, apikey, content-type, x-admin-token",
    "access-control-allow-methods": "GET, POST, OPTIONS",
  };
}

function json(obj: unknown, cors: Record<string, string>, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "content-type": "application/json; charset=utf-8" },
  });
}

function sb() {
  return createClient(SB_URL, SRK, { auth: { persistSession: false } });
}

const PAGE_URL = "https://yb471.github.io/health-dashboard/";

function getPage(): Response {
  return Response.redirect(PAGE_URL, 302);
}

// ---- Per-IP brute-force throttle ---------------------------------------------------
// All throttle helpers fail OPEN on infrastructure errors so a DB hiccup can never lock
// the legitimate user out; a lockout is only enforced when the table explicitly says so.
const THROTTLE_WINDOW_MS = 15 * 60 * 1000; // failures counted within a 15-min window
const THROTTLE_THRESHOLD = 8;              // lock after this many failures in the window
const THROTTLE_LOCK_MS = 15 * 60 * 1000;   // lockout duration

function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for") || "";
  return xff.split(",")[0].trim();
}

async function throttleRetryAfter(client: ReturnType<typeof sb>, ip: string): Promise<number> {
  if (!ip) return 0;
  try {
    const { data } = await client.from("auth_throttle").select("locked_until").eq("ip", ip).maybeSingle();
    if (data && data.locked_until) {
      const until = new Date(data.locked_until).getTime();
      const now = Date.now();
      if (until > now) return Math.ceil((until - now) / 1000);
    }
  } catch (_e) { /* fail open */ }
  return 0;
}

async function registerFail(client: ReturnType<typeof sb>, ip: string): Promise<void> {
  if (!ip) return;
  try {
    const now = Date.now();
    const { data } = await client.from("auth_throttle").select("fails,first_fail").eq("ip", ip).maybeSingle();
    let fails = 1;
    let firstFail = new Date(now).toISOString();
    if (data && data.first_fail) {
      const ff = new Date(data.first_fail).getTime();
      if (now - ff < THROTTLE_WINDOW_MS) { fails = (data.fails || 0) + 1; firstFail = data.first_fail; }
    }
    const lockedUntil = fails >= THROTTLE_THRESHOLD ? new Date(now + THROTTLE_LOCK_MS).toISOString() : null;
    await client.from("auth_throttle").upsert({ ip, fails, first_fail: firstFail, locked_until: lockedUntil, updated_at: new Date(now).toISOString() });
  } catch (_e) { /* ignore */ }
}

async function clearThrottle(client: ReturnType<typeof sb>, ip: string): Promise<void> {
  if (!ip) return;
  try { await client.from("auth_throttle").delete().eq("ip", ip); } catch (_e) { /* ignore */ }
}

async function allLabs(client: ReturnType<typeof sb>) {
  const rows: unknown[] = [];
  const page = 1000;
  let from = 0;
  for (;;) {
    const { data, error } = await client
      .from("lab_results")
      .select("marker,category,test_date,value_num,value_text,unit,ref_low,ref_high,flag,source")
      .neq("source", "setup_test")
      .order("test_date", { ascending: true })
      .order("marker", { ascending: true })
      .range(from, from + page - 1);
    if (error) throw new Error("lab_results: " + error.message);
    if (!data || data.length === 0) break;
    rows.push(...data);
    if (data.length < page) break;
    from += page;
  }
  return rows;
}

async function getAdminToken(client: ReturnType<typeof sb>): Promise<string> {
  const { data } = await client.from("app_config").select("value").eq("key", "admin_token").single();
  return (data && data.value) || "";
}

// Storage paths are attacker-influencable, so constrain them: no traversal, no leading slash,
// a conservative charset, and a .pdf suffix (all managed documents are PDFs).
function safeStoragePath(path: string): boolean {
  if (!path || path.length > 255) return false;
  if (path.includes("..") || path.startsWith("/") || path.includes("\\") || path.includes("\0")) return false;
  return /^[A-Za-z0-9][A-Za-z0-9_\-./]*\.pdf$/.test(path);
}

const ALLOWED_UPLOAD_CT = new Set(["application/pdf", "application/octet-stream"]);
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024; // 25 MB cap to avoid unbounded buffering

async function uploadDoc(req: Request, url: URL, cors: Record<string, string>): Promise<Response> {
  const client = sb();
  const token = req.headers.get("x-admin-token") || "";
  const dbTok = await getAdminToken(client);
  if (!dbTok || token !== dbTok) return json({ error: "unauthorized" }, cors, 401);
  const path = url.searchParams.get("path") || "";
  if (!safeStoragePath(path)) return json({ error: "invalid_path" }, cors, 400);
  const lenHeader = Number(req.headers.get("content-length") || "0");
  if (lenHeader && lenHeader > MAX_UPLOAD_BYTES) return json({ error: "too_large" }, cors, 413);
  let ct = (req.headers.get("content-type") || "application/octet-stream").split(";")[0].trim().toLowerCase();
  if (!ALLOWED_UPLOAD_CT.has(ct)) return json({ error: "unsupported_type" }, cors, 415);
  const bytes = new Uint8Array(await req.arrayBuffer());
  if (!bytes.length) return json({ error: "empty_body" }, cors, 400);
  if (bytes.length > MAX_UPLOAD_BYTES) return json({ error: "too_large" }, cors, 413);
  // Verify the content actually is a PDF (magic bytes %PDF-) rather than trusting the header.
  if (!(bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)) {
    return json({ error: "not_a_pdf" }, cors, 415);
  }
  ct = "application/pdf";
  const { error } = await client.storage
    .from("lab-documents")
    .upload(path, bytes, { contentType: ct, upsert: true });
  if (error) return json({ error: "server" }, cors, 500);
  return json({ ok: true, path, bytes: bytes.length }, cors);
}

async function deleteDoc(req: Request, url: URL, cors: Record<string, string>): Promise<Response> {
  const client = sb();
  const token = req.headers.get("x-admin-token") || "";
  const dbTok = await getAdminToken(client);
  if (!dbTok || token !== dbTok) return json({ error: "unauthorized" }, cors, 401);
  const path = url.searchParams.get("path") || "";
  if (!safeStoragePath(path)) return json({ error: "invalid_path" }, cors, 400);
  const { error } = await client.storage.from("lab-documents").remove([path]);
  if (error) return json({ error: "server" }, cors, 500);
  return json({ ok: true, removed: path }, cors);
}

// deno-lint-ignore no-explicit-any
async function logReaction(body: any, cors: Record<string, string>): Promise<Response> {
  const client = sb();
  const r = (body && body.reaction) || {};
  const cap = (s: unknown, n: number) => (s == null ? null : String(s).slice(0, n));
  const toIntOrNull = (v: unknown, lo: number, hi: number): number | null | undefined => {
    if (v === "" || v == null) return null;
    const n = Number(v);
    if (!Number.isFinite(n)) return undefined; // signal invalid
    return Math.max(lo, Math.min(hi, Math.round(n)));
  };
  const onset = toIntOrNull(r.onset_minutes, 0, 100000);
  const severity = toIntOrNull(r.severity, 0, 10);
  if (onset === undefined || severity === undefined) return json({ error: "invalid_number" }, cors, 400);
  const date = r.reaction_date == null || r.reaction_date === "" ? null : String(r.reaction_date);
  if (date != null && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ error: "invalid_date" }, cors, 400);
  const row = {
    food_de: cap(r.food_de, 200) || null,
    reaction_date: date,
    portion: cap(r.portion, 200) || null,
    preparation: cap(r.preparation, 500) || null,
    symptoms: cap(r.symptoms, 1000) || null,
    onset_minutes: onset,
    severity: severity,
    suspected_mechanism: cap(r.suspected_mechanism, 200) || null,
    notes: cap(r.notes, 2000) || null,
  };
  if (!row.food_de && !row.symptoms) return json({ error: "empty" }, cors, 400);
  const { error } = await client.from("food_reactions").insert(row);
  if (error) return json({ error: "server" }, cors, 500);
  return json({ ok: true }, cors);
}

// Batch-sign all document URLs in one Storage round-trip instead of ~31 sequential calls.
// Falls back to per-doc signing if the batch call is unavailable, so links never regress.
async function signDocs(client: ReturnType<typeof sb>, docs: { storage_path?: string }[]) {
  const out: Record<string, string> = {};
  const paths = docs.map((d) => d.storage_path).filter((p): p is string => !!p);
  if (!paths.length) return out;
  try {
    const { data, error } = await client.storage.from("lab-documents").createSignedUrls(paths, 3600);
    if (!error && data) {
      for (const item of data) {
        if (item && item.path && item.signedUrl) out[item.path] = item.signedUrl;
      }
      if (Object.keys(out).length) return out;
    }
  } catch (_e) { /* fall through to per-doc signing */ }
  for (const p of paths) {
    const { data } = await client.storage.from("lab-documents").createSignedUrl(p, 3600);
    if (data && data.signedUrl) out[p] = data.signedUrl;
  }
  return out;
}

async function getData(cors: Record<string, string>): Promise<Response> {
  const client = sb();
  try {
    // Only the tables the client actually renders are fetched. (diagnoses/medications/
    // recommendations and app_config "highlights" were fetched-but-never-used and were dropped.)
    const [labs, rep, fg, recs, docs] = await Promise.all([
      allLabs(client),
      client.from("clinical_reports").select("id,report_date,doctor,specialty,report_type,summary,summary_ru,source").order("report_date", { ascending: false }),
      client.from("food_guide").select("food_de,food_group,verdict,tested,r_igg,r_igg4,r_ige,r_hist,r_gut,r_lact,r_gluten,r_rec,rec_note,gi,protein_100g,fiber_100g,fat_100g,kcal_100g,hist_score,buy,cook,store,restaurant,hist_note,gut_score,gut_note,phase,recovery_priority,primary_reason,clinical_comment_ru"),
      client.from("lab_recommendations").select("rec_date,lab_name,title,body,body_ru,source").order("rec_date", { ascending: false }),
      client.from("documents").select("doc_date,doc_type,title,filename,storage_path,linked_report_id,uploaded").order("doc_date", { ascending: false }),
    ]);

    const errors: string[] = [];
    for (const [name, r] of [["clinical_reports", rep], ["food_guide", fg], ["lab_recommendations", recs], ["documents", docs]] as const) {
      if ((r as { error?: { message: string } }).error) errors.push(name);
    }
    if (errors.length) return json({ error: "server", detail: "load_failed" }, cors, 500);

    const docRows = (docs.data || []) as { storage_path?: string }[];

    // signDocs, food_panels and food_reactions have no cross-dependency: run them concurrently.
    const [signed, panelsRes, reactionsRes] = await Promise.all([
      signDocs(client, docRows),
      client.from("food_panels").select("panel,lab,test_date,food,food_ru,grp,value_num,unit,level").order("value_num", { ascending: false }),
      client.from("food_reactions").select("id,food_de,reaction_date,portion,preparation,symptoms,onset_minutes,severity,suspected_mechanism,notes").order("reaction_date", { ascending: false }).order("created_at", { ascending: false }),
    ]);

    return json({
      labs,
      rep: rep.data || [],
      fg: fg.data || [],
      recs: recs.data || [],
      docs: docRows,
      signed,
      panels: (panelsRes as { data?: unknown[] }).data || [],
      reactions: (reactionsRes as { data?: unknown[] }).data || [],
    }, cors);
  } catch (_e) {
    return json({ error: "server", detail: "load_failed" }, cors, 500);
  }
}

Deno.serve(async (req) => {
  const cors = corsHeaders(req);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  if (req.method === "GET") return getPage();

  if (req.method === "POST") {
    const url = new URL(req.url);
    if (url.searchParams.get("admin") === "doc") return await uploadDoc(req, url, cors);
    if (url.searchParams.get("admin") === "del") return await deleteDoc(req, url, cors);
    if (!PW) return json({ error: "not_configured" }, cors, 503);

    const ip = clientIp(req);
    const throttleClient = sb();
    const retryAfter = await throttleRetryAfter(throttleClient, ip);
    if (retryAfter > 0) {
      return new Response(JSON.stringify({ error: "too_many_attempts", retry_after: retryAfter }), {
        status: 429,
        headers: { ...cors, "content-type": "application/json; charset=utf-8", "retry-after": String(retryAfter) },
      });
    }

    // deno-lint-ignore no-explicit-any
    let body: any = {};
    try { body = await req.json(); } catch (_e) { /* ignore */ }
    if (!body || body.password !== PW) {
      await registerFail(throttleClient, ip);
      return json({ error: "unauthorized" }, cors, 401);
    }
    await clearThrottle(throttleClient, ip);

    if (body.action === "logreaction") return await logReaction(body, cors);
    return await getData(cors);
  }

  return new Response("method not allowed", { status: 405, headers: cors });
});
