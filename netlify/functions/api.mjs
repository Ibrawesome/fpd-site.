import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const ADMIN_USER = process.env.ADMIN_USER || "IBRAWESOME";
const ADMIN_PASS = process.env.ADMIN_PASS || "6793";
const SECRET = process.env.AUTH_SECRET || "fpd::" + ADMIN_PASS;
const store = () => getStore({ name: "fpd-idcards", consistency: "strong" });

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
const fail = (msg, status = 400) => json({ error: msg }, status);

const hashPw = (pw) => {
  const salt = crypto.randomBytes(12).toString("hex");
  return "s:" + salt + ":" + crypto.scryptSync(String(pw), salt, 32).toString("hex");
};
const checkPw = (pw, stored) => {
  if (!stored || !stored.startsWith("s:")) return false;
  const [, salt, h] = stored.split(":");
  const a = Buffer.from(crypto.scryptSync(String(pw), salt, 32).toString("hex"));
  const b = Buffer.from(h);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sign = (p) => {
  const body = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + 12 * 3600e3 })).toString("base64url");
  return body + "." + crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
};
const readToken = (t) => {
  try {
    const [body, sig] = String(t).split(".");
    const good = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
    if (sig !== good) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
};

const skey = (regno) => "s/" + encodeURIComponent(regno);
const getStudent = (regno) => store().get(skey(regno), { type: "json" });
const putStudent = (s) => store().setJSON(skey(s.regno), s);
const getMeta = async () => (await store().get("meta", { type: "json" })) || { settings: {}, nextSeq: 1, printLog: [] };
const putMeta = (m) => store().setJSON("meta", m);
const allStudents = async () => {
  const { blobs } = await store().list({ prefix: "s/" });
  const list = await Promise.all(blobs.map((b) => store().get(b.key, { type: "json" })));
  return list.filter(Boolean);
};
const pub = (s) => { const { password, ...rest } = s; return rest; };
const pad4 = (n) => String(n).padStart(4, "0");
const addYears = (iso, y) => { const d = new Date(iso); d.setFullYear(d.getFullYear() + y); return d.toISOString().slice(0, 10); };

export default async (req) => {
  if (req.method !== "POST") return fail("POST only", 405);
  const action = new URL(req.url).pathname.split("/").filter(Boolean).pop();
  let b = {};
  try { b = await req.json(); } catch {}
  const tok = readToken(b.token);

  try {
    if (action === "settings") return json({ settings: (await getMeta()).settings });

    if (action === "student-register") {
      const st = b.student || {};
      const regno = String(st.regno || "").trim().toUpperCase();
      if (!regno || !st.name || !st.password) return fail("Please fill in every field.");
      if (String(st.photo || "").length > 1.5e6) return fail("Photo is too large.");
      if (await getStudent(regno)) return fail("That registration number is already registered. Please log in instead.", 409);
      const meta = await getMeta();
      const seq = meta.nextSeq || 1;
      meta.nextSeq = seq + 1;
      const issue = new Date().toISOString().slice(0, 10);
      const s = {
        regno, password: hashPw(st.password), name: st.name, dept: st.dept || "", faculty: st.faculty || "",
        phone: st.phone || "", photo: st.photo || null, approved: false,
        cardNo: (meta.settings.cardPrefix || "FPD") + "/" + new Date().getFullYear() + "/" + pad4(seq),
        issueDate: issue, expiryDate: addYears(issue, meta.settings.validityYears || 3),
        createdAt: new Date().toISOString(),
      };
      await putStudent(s);
      await putMeta(meta);
      return json({ token: sign({ r: "student", id: regno }), student: pub(s), settings: meta.settings });
    }

    if (action === "student-login") {
      const regno = String(b.regno || "").trim().toUpperCase();
      const s = await getStudent(regno);
      if (!s || !checkPw(b.password, s.password)) return fail("Registration number or password is incorrect.", 401);
      return json({ token: sign({ r: "student", id: regno }), student: pub(s), settings: (await getMeta()).settings });
    }

    if (action === "student-me" || action === "student-save") {
      if (!tok || tok.r !== "student") return fail("Please log in again.", 401);
      const s = await getStudent(tok.id);
      if (!s) return fail("Account not found.", 404);
      if (action === "student-save") {
        const n = b.student || {};
        for (const k of ["name", "dept", "faculty", "phone", "photo"]) if (k in n) s[k] = n[k];
        if (n.password) s.password = hashPw(n.password);
        await putStudent(s);
        if (Array.isArray(b.log) && b.log.length) {
          const meta = await getMeta();
          b.log.forEach((e) => { if (e.regno === s.regno) meta.printLog.push(e); });
          await putMeta(meta);
        }
      }
      return json({ student: pub(s) });
    }

    if (action === "admin-login") {
      if (b.username !== ADMIN_USER || b.password !== ADMIN_PASS) return fail("Incorrect username or password.", 401);
      return json({ token: sign({ r: "admin" }) });
    }

    if (action === "admin-load" || action === "admin-sync") {
      if (!tok || tok.r !== "admin") return fail("Please log in again.", 401);
      const meta = await getMeta();
      if (action === "admin-sync") {
        for (const [regno, s] of Object.entries(b.upserts || {})) {
          const old = await getStudent(regno);
          const next = { ...s };
          next.password = s.password ? hashPw(s.password) : old?.password;
          await putStudent(next);
        }
        for (const regno of b.deletes || []) await store().delete(skey(regno));
        if (b.settings) meta.settings = b.settings;
        meta.nextSeq = Math.max(meta.nextSeq || 1, b.nextSeq || 1);
        if (b.logClear) meta.printLog = [];
        if (Array.isArray(b.logAdd)) meta.printLog.push(...b.logAdd);
        await putMeta(meta);
        return json({ ok: true });
      }
      const students = {};
      (await allStudents()).forEach((s) => { students[s.regno] = { ...pub(s), password: "" }; });
      return json({ students, settings: meta.settings, nextSeq: meta.nextSeq, printLog: meta.printLog });
    }

    if (action === "verify") {
      const text = String(b.text || "").trim();
      const m = text.match(/^FPD-ID\|([^|]+)\|([^|]+)$/);
      const cardNo = m ? m[1] : text, regno = m ? m[2] : null;
      let s = (regno && (await getStudent(regno))) || (await getStudent(cardNo.toUpperCase()));
      if (!s) s = (await allStudents()).find((x) => x.cardNo === cardNo);
      if (!s) return json({ found: null });
      const { regno: r, name, dept, faculty, cardNo: c, photo, approved, expiryDate } = s;
      return json({ found: { regno: r, name, dept, faculty, cardNo: c, photo, approved, expiryDate } });
    }

    return fail("Unknown action", 404);
  } catch (e) {
    return fail("Server error: " + e.message, 500);
  }
};
