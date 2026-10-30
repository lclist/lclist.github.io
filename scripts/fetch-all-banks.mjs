// 全银行净值定时刷新（GitHub Actions runner 上运行）
// - 读取仓库内 产品数据.json 的 registry，得到全部有效产品（custom，含 patches；无 deleted 墓碑）
// - jsb/ceb：走本机/runner 的 puppeteer-core + 系统 Chrome（线上 Worker 无浏览器，抓不到）
// - 其余银行：直接调线上 Cloudflare Worker 的 /api/product（复用其 25 家银行抓取逻辑，已免登录直连）
// - 合并策略：保留基线 净值数据.json 的静态字段（risk/holdDays/established/regCode/kind/gha），
//   仅用抓到的结果覆盖动态字段（series/nav/navDate/navVia/navPort/name/manager/benchmark/quota）
// - 仅当 observer_lookup_real 内容真正变化时才写盘并更新 savedAt（避免每小时空跑产生无意义 commit）

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, ".."); // ghpages 仓库根
const NAV_FILE = path.join(ROOT, "净值数据.json");
const REG_FILE = path.join(ROOT, "产品数据.json");

const WORKER_BASE = process.env.WORKER_BASE || "https://lclist-finance-api.lclist.workers.dev";
const JSB_BANK = "jsb";
const CEB_BANK = "ceb";
const WORKER_CONCURRENCY = 6;
const WORKER_TIMEOUT_MS = 12000;
const JSB_CEB_TIMEOUT_MS = 30000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- 工具 ---------- */

function safeParseReg(raw) {
  let v = raw;
  if (typeof v === "string") {
    try { v = JSON.parse(v); } catch (e) { return null; }
  }
  if (typeof v === "string") {
    try { v = JSON.parse(v); } catch (e) { return null; }
  }
  return v;
}

function parseHoldDays(term) {
  if (term == null) return null;
  if (String(term).trim() === "daily" || String(term).trim() === "每日开放") return 1;
  const m = String(term).match(/(\d+)/);
  return m ? Number(m[1]) : null;
}

function trimBenchmark(s) {
  if (!s || typeof s !== "string") return s;
  if (s.length <= 150) return s;
  let cut = 150;
  for (let i = 150; i >= 0; i--) {
    if (s[i] === "。" || s[i] === "；" || s[i] === ";" || s[i] === ".") { cut = i + 1; break; }
  }
  return s.slice(0, cut);
}

/* ---------- 读取 registry，得到全部有效产品 ---------- */

function loadProducts() {
  const p = JSON.parse(fs.readFileSync(REG_FILE, "utf8"));
  const reg = safeParseReg(p.data && p.data.observer_reg_v1);
  if (!reg) return [];
  const custom = Array.isArray(reg.custom) ? reg.custom : Object.values(reg.custom || {});
  const items = [];
  const flat = (x) => {
    if (Array.isArray(x)) x.forEach(flat);
    else if (x && typeof x === "object") items.push(x);
  };
  custom.forEach(flat);
  const patches = reg.patches || {};
  const out = [];
  for (const r of items) {
    if (!r || !r.code) continue;
    const code = String(r.code).toUpperCase();
    const patch = patches[code] || {};
    out.push({
      code,
      bank: r.bank || patch.bank || null,
      name: r.name || patch.name || null,
      manager: r.manager || patch.manager || null,
      risk: r.risk != null ? r.risk : patch.risk != null ? patch.risk : null,
      holdDays: r.holdDays != null ? r.holdDays : patch.holdDays != null ? parseHoldDays(patch.holdDays) : null,
      established: r.established || patch.established || null,
      benchmark: r.benchmark && r.benchmark !== "—" ? r.benchmark : patch.benchmark || null,
      regCode: r.regCode || patch.regCode || null,
    });
  }
  return out;
}

/* ---------- jsb/ceb：浏览器抓取 + 归一化 ---------- */

function normalizeJsbCeb(res, prev, bank, st) {
  const obj = Object.assign({}, prev);
  obj.code = res.code || prev.code;
  obj.name = res.name != null ? res.name : prev && prev.name != null ? prev.name : st && st.name != null ? st.name : null;
  obj.manager = res.manager != null ? res.manager : prev && prev.manager != null ? prev.manager : st && st.manager != null ? st.manager : null;
  // 2026-10-30：jsb/ceb 浏览器腿同样**按日期并集**、不覆盖式替换——
  //   该腿有时只回部分历史（如 J09652 242→91），覆盖会把整段历史冲掉。
  if (Array.isArray(res.series) && res.series.length) {
    obj.series = mergeSeriesByDate(prev && Array.isArray(prev.series) ? prev.series : null, res.series, true);
  }
  else if (prev && Array.isArray(prev.series)) obj.series = prev.series;
  obj.nav = res.nav != null ? res.nav : prev && prev.nav != null ? prev.nav : null;
  obj.navDate = res.navDate != null ? res.navDate : prev && prev.navDate != null ? prev.navDate : null;
  obj.remainQuota = res.remainQuota != null ? Number(res.remainQuota) : prev && prev.remainQuota != null ? Number(prev.remainQuota) : null;
  obj.remainQuotaPct = res.remainQuotaPct != null ? res.remainQuotaPct : prev && prev.remainQuotaPct != null ? prev.remainQuotaPct : null;
  obj.saleStatus = res.saleStatus || (prev && prev.saleStatus) || null;
  obj.currency = res.currency || (prev && prev.currency) || null;
  obj.quotaState = res.quotaState || (prev && prev.quotaState) || null;
  obj.quotaText = res.quotaText || (prev && prev.quotaText) || null;
  obj.quotaManual = (prev && prev.quotaManual) || null;
  obj.benchmark = res.benchmark != null ? trimBenchmark(res.benchmark) : prev && prev.benchmark != null ? prev.benchmark : st && st.benchmark != null ? trimBenchmark(st.benchmark) : null;
  obj.benchmarkFull = res.benchmark != null ? res.benchmark : prev && (prev.benchmarkFull || prev.benchmark) ? prev.benchmarkFull || prev.benchmark : null;
  obj.regCode = res.regCode != null ? res.regCode : prev && prev.regCode != null ? prev.regCode : st && st.regCode != null ? st.regCode : null;
  obj.established = res.established != null ? res.established : prev && prev.established != null ? prev.established : st && st.established != null ? st.established : null;
  obj.navVia = res.navVia || (prev && prev.navVia) || null;
  obj.navPort = res.navPort != null ? res.navPort : prev && prev.navPort != null ? prev.navPort : null;
  obj.bank = bank || (prev && prev.bank) || null;
  obj.gha = true; // 标记：前端 overlay 据此识别云端刷新记录
  return obj;
}

async function fetchJsbCeb(products) {
  const sub = products.filter((p) => p.bank === JSB_BANK || p.bank === CEB_BANK);
  if (!sub.length) return {};
  const jsbMod = await import(pathToFileURL(path.join(ROOT, "scrape", "jsb_app.mjs")).href);
  const cebMod = await import(pathToFileURL(path.join(ROOT, "scrape", "ceb_direct_nav.mjs")).href);
  const out = {};
  for (const p of sub) {
    let res = null;
    for (let attempt = 1; attempt <= 3 && !res; attempt++) {
      if (attempt > 1) { console.log("[all] " + p.code + " 第" + attempt + "次重试"); await sleep(2500); }
      try {
        if (p.bank === JSB_BANK) {
          const o = await jsbMod.jsbAppByCode(p.code, { timeoutMs: JSB_CEB_TIMEOUT_MS });
          if (o) res = { ...o, bank: JSB_BANK, regCode: o.registryCode || p.regCode || null };
        } else {
          const r = await cebMod.cebWebNav(p.code, { timeoutMs: JSB_CEB_TIMEOUT_MS });
          if (r && Array.isArray(r.navs) && r.navs.length) {
            const series = r.navs.map((n) => [n.date, n.nav, null]);
            res = {
              code: p.code, name: p.name || r.name || null, manager: r.manager || p.manager || null,
              series, kind: "nav", bank: CEB_BANK, navVia: "ceb-web", navPort: "web",
            };
          }
        }
      } catch (e) {
        console.warn("[all] " + p.code + " 抓取异常：" + (e && e.message));
      }
    }
    if (res) out[p.code] = { res, bank: p.bank, st: p };
  }
  try { await jsbMod.closeJsbBrowser(); } catch (e) {}
  try { await cebMod.closeCebWebBrowser(); } catch (e) {}
  return out;
}

/* ---------- 其余银行：调线上 Worker ---------- */

// 已有记录的最后一个净值日（增量抓取的 since）——没有序列则传 null（走全量）
function lastDateOf(rec) {
  const s = rec && Array.isArray(rec.series) ? rec.series : null;
  if (!s || !s.length) return null;
  for (let i = s.length - 1; i >= 0; i--) if (s[i] && s[i][0]) return String(s[i][0]);
  return null;
}

// 按日期并集合并（旧序列 + 新序列）
// ⚠ 2026-10-30 起**永不覆盖式替换**：上游有时只回部分历史（如 jsb 242→91、boc 415→230），
//   或来源切换（bob→fminbank）时新序列点数更少 —— 直接替换会把整段历史冲掉。
// newWins：同日期冲突时是否以新值为准。
//   · 同来源 → true（可修正上游更正的旧值）
//   · 异来源 → false（保留旧值，避免两种口径的单位净值/万份收益混在一段曲线里）
function mergeSeriesByDate(prev, neu, newWins) {
  const m = new Map();
  for (const p of (prev || [])) if (p && p[0]) m.set(String(p[0]), p);
  for (const p of (neu || [])) if (p && p[0]) {
    const k = String(p[0]);
    if (m.has(k) && newWins === false) continue;
    m.set(k, p);
  }
  return [...m.values()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

async function fetchViaWorker(code, bank, since) {
  // since：增量（只补缺失/新增点），避免每小时重翻全量历史（中邮等 25 页产品省时显著）
  // noCache=1：CDN 缓存 TTL 6h，同一 since 的结果会被缓存住 → 主动回源，保证当轮真实
  const url =
    WORKER_BASE + "/api/product?code=" + encodeURIComponent(code) +
    "&issuer=" + encodeURIComponent(bank) + "&mode=nav&noCache=1" +
    (since ? "&since=" + encodeURIComponent(since) : "");
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), WORKER_TIMEOUT_MS);
  try {
    const resp = await fetch(url, { signal: ctrl.signal });
    if (!resp.ok) return null;
    const R = await resp.json();
    return R;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function mergeWorkerRecord(existing, R) {
  if (!R || !R.code) return null;
  const seriesRaw = (R.nav && Array.isArray(R.nav.series) && R.nav.series) ||
    (Array.isArray(R.series) && R.series) || null;
  if (!seriesRaw || !seriesRaw.length) return null;
  const series = seriesRaw.map((p) =>
    Array.isArray(p) ? (p.length >= 3 ? [p[0], p[1], p[2]] : [p[0], p[1], null]) : p
  );
  const last = series[series.length - 1];
  const merged = Object.assign({}, existing);
  merged.code = R.code;
  merged.bank = R.navVia || R.source || existing.bank || null;
  merged.navVia = R.navVia || existing.navVia || null;
  merged.navPort = R.navPort || existing.navPort || null;
  merged.name = R.name || existing.name || null;
  merged.manager = R.manager || existing.manager || null;
  if (R.benchmark) merged.benchmark = R.benchmark;
  if (R.quota != null) merged.quota = R.quota;
  // 2026-10-30：序列一律按日期并集，**永不覆盖式替换**（避免上游只回部分历史时冲掉整段历史）
  const isInc = !!(R.nav && R.nav.navIncremental);
  const prevSeries = existing && Array.isArray(existing.series) ? existing.series : null;
  const sameSrc = !!(existing && existing.navVia && R.navVia && String(existing.navVia) === String(R.navVia));
  const finalSeries = (isInc || (prevSeries && prevSeries.length))
    ? mergeSeriesByDate(prevSeries, series, isInc ? true : sameSrc)
    : series;
  merged.series = finalSeries;
  const lastF = finalSeries[finalSeries.length - 1];
  merged.nav = lastF ? lastF[1] : existing.nav;
  merged.navDate = lastF ? lastF[0] : existing.navDate;
  // 保留 existing 的静态字段：risk / holdDays / established / regCode / kind / gha
  return merged;
}

async function fetchWorkerBatch(products, real) {
  const out = {};
  let idx = 0;
  const worker = async () => {
    while (true) {
      const i = idx++;
      if (i >= products.length) break;
      const p = products[i];
      try {
        // 增量：带上本地已有序列的最后净值日 → Worker 只补缺失/新增点
        const R = await fetchViaWorker(p.code, p.bank, lastDateOf(real ? real[p.code] : null));
        if (R) out[p.code] = R;
      } catch (e) {
        console.warn("[all] " + p.code + " Worker 抓取失败：" + (e && e.message));
      }
    }
  };
  const pool = [];
  for (let k = 0; k < WORKER_CONCURRENCY; k++) pool.push(worker());
  await Promise.all(pool);
  return out;
}

/* ---------- 主流程 ---------- */

async function main() {
  const t0 = Date.now();
  const products = loadProducts();
  if (!products.length) {
    console.error("[all] registry 中未发现任何有效产品，退出");
    process.exit(0);
  }
  console.log("[all] registry 有效产品：" + products.length + " 个，覆盖银行：" +
    Array.from(new Set(products.map((p) => p.bank))).join(","));

  const outer = JSON.parse(fs.readFileSync(NAV_FILE, "utf8"));
  const realRaw = outer.data && outer.data.observer_lookup_real;
  const real = typeof realRaw === "string" ? JSON.parse(realRaw) : realRaw || {};

  // 1) jsb/ceb 浏览器抓取
  const jsbCeb = await fetchJsbCeb(products);
  for (const code in jsbCeb) {
    const { res, bank, st } = jsbCeb[code];
    real[code] = normalizeJsbCeb(res, real[code] || null, bank, st);
    console.log("[all] " + code + " (" + bank + ") ✓ 浏览器抓取完成");
  }

  // 2) 其余银行走 Worker
  const others = products.filter((p) => p.bank !== JSB_BANK && p.bank !== CEB_BANK && p.bank);
  const workerResults = await fetchWorkerBatch(others, real);
  let merged = 0, skipped = 0;
  for (const p of others) {
    const R = workerResults[p.code];
    if (!R) { skipped++; continue; }
    const mergedRec = mergeWorkerRecord(real[p.code] || null, R);
    if (!mergedRec) { skipped++; continue; }
    real[p.code] = mergedRec;
    merged++;
  }
  console.log("[all] Worker 抓取：成功合并 " + merged + " / 跳过(无数据) " + skipped);

  // 3) 孤儿清理：移除不在活跃 registry 的 nav 记录，保证 净值数据.json 与 registry 永远一致、不留孤儿
  const activeCodes = new Set(products.map((p) => p.code));
  let pruned = 0;
  for (const code of Object.keys(real)) {
    if (!activeCodes.has(code)) { delete real[code]; pruned++; }
  }
  if (pruned) console.log("[all] 孤儿清理：移除 " + pruned + " 条不在 registry 的 nav 记录");

  // 4) 写回（仅变化时）
  const prevRealStr = realRaw || "";
  const newRealStr = JSON.stringify(real);
  outer.data = outer.data || {};
  outer.count = Object.keys(real).length;
  if (newRealStr === prevRealStr) {
    console.log("[all] 完成：净值无变化，跳过写盘（用时 " + ((Date.now() - t0) / 1000).toFixed(1) + "s）");
    return;
  }
  outer.data.observer_lookup_real = newRealStr;
  outer.savedAt = new Date().toISOString();
  fs.writeFileSync(NAV_FILE, JSON.stringify(outer), "utf8");
  console.log("[all] 完成：已写回 " + path.basename(NAV_FILE) + "（含孤儿清理 " + pruned + " 条，用时 " + ((Date.now() - t0) / 1000).toFixed(1) + "s）");
}

main().catch((e) => {
  console.error("[all] 致命错误：" + (e && e.stack || e));
  process.exit(1);
});
