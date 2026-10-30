/* 江苏银行 App 端口（mbank5h5.jsbchina.cn 手机银行 H5）产品抓取（仅本机 Node 用）
 *
 * ============================ 端口本质（2026-10-18 二次打通）============================
 * 入口页：https://mbank5h5.jsbchina.cn/mbank/page/indexJsb.html   ← 无参即可加载加密库
 *   （页面是 SPA，body 为空，但 YT / jsbankAES / getkey 公钥链路已就绪，可直接发业务请求）
 * 业务接口（POST，加密）：
 *   H5queryFinanceDetail.do   入参 {"prdCode":"J04946"}                    → 详情（七字段+额度+登记编码）
 *   H5queryTbprddaily.do      入参 {prdCode, TACode:"Y04",
 *                                  prodTemplateNo:"D300", dateFlag:"4",
 *                                  prdattr:"4"}                            → 净值序列
 *
 * ★ 关键结论（实测）：**业务入参只有 prdCode**，shareCode 只作为公共头
 *   `_currentUrl` 的一部分，与产品无关 → 因此「不需要分享链接」，任意产品码都能直查。
 * ★ dateFlag 语义（实测 J04946）：
 *   1 = 近 3 月(60 点)  2 = 近 6 月(122)  3 = 近 1 年(246)  4 = 成立以来(324) ★
 *   → 统一用 dateFlag=4 一次拿全量，无需滚动/点击累加（旧方案的最大不稳定源已消除）。
 * 加密协议 YT.SecurityJSBANK = AES-CBC(明文, 会话密钥) + RSA(会话密钥, getkey.do 公钥) + MD5，
 *   以 \u001d(0x1F) 拼接。此处不复刻算法，而是**在页面上下文里调用页面自己的 YT.ajaxData**，
 *   加密/解密/公钥刷新全由页面完成，只需取回调对象。
 *
 * ============================ result 关键字段（实测）============================
 *   J04946 苏银理财恒源天添鑫12号A：每日开放(T+1)/R2/登记 Z7003125000145/成立 2025-07-03/
 *          基准 央行活期+0.30%/额度 ≈2.68亿/净值 324 点（2025-06-26~2026-10-15）
 *   J09652 苏银理财恒源灵动最短持有180天10号A：最低持有180天/R2/成立 2025-10-30/
 *          基准 中债-新综合财富(1年以下)×60%+半年定存×40%/额度 ≈4.73亿/净值 81 点（成立以来全量）
 * ========================================================================== */

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const JSB_APP_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.40(0x1800282a) NetType/WIFI Language/zh_CN";

// 无参种子页：只用于加载 YT 加密库，本身不发起业务请求
const JSB_SEED_URL = "https://mbank5h5.jsbchina.cn/mbank/page/indexJsb.html";
const JSB_API_BASE = "https://mbank5h5.jsbchina.cn/mbank//finance/";

const CHROME_CANDIDATES = [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
].filter(Boolean);

let _puppeteer;
function puppeteerCore() {
  if (_puppeteer !== undefined) return _puppeteer;
  for (const spec of ["puppeteer-core", "C:/Users/a/.workbuddy/binaries/node/workspace/node_modules/puppeteer-core", process.env.JSB_PUPPETEER].filter(Boolean)) {
    try { _puppeteer = require(spec); return _puppeteer; } catch (e) { /* 下一个 */ }
  }
  _puppeteer = null;
  return null;
}

let _browser = null;
let _launching = null; // 2026-10-22：并发启动去重——多产品同时抓时只拉一个 Chrome（旧实现并发下会拉出多个实例互相争抢，冷启动 25s+）
async function sharedBrowser() {
  const pptr = puppeteerCore();
  if (!pptr) return null;
  if (_browser && _browser.connected) return _browser;
  if (_launching) return _launching; // 已有启动在进行 → 复用同一次启动
  _launching = (async () => {
    const fs = require("node:fs");
    const exe = CHROME_CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch (e) { return false; } });
    if (!exe) return null;
    _browser = await pptr.launch({
      executablePath: exe,
      headless: "new",
      args: ["--no-sandbox", "--disable-dev-shm-usage", "--lang=zh-CN", "--disable-blink-features=AutomationControlled", "--disable-web-security"],
      defaultViewport: { width: 390, height: 844, isMobile: true, hasTouch: true },
    });
    return _browser;
  })();
  try { return await _launching; } finally { _launching = null; }
}
export async function closeJsbBrowser() {
  try { if (_seedPage && !_seedPage.isClosed()) await _seedPage.close(); } catch (e) {}
  _seedPage = null;
  try { if (_browser && _browser.connected) await _browser.close(); } catch (e) {}
  _browser = null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 带超时的 page.evaluate：单条 evaluate 卡死不应拖垮整次抓取
async function evalT(page, fn, ms = 6000) {
  return Promise.race([
    page.evaluate(fn),
    sleep(ms).then(() => null),
  ]).catch(() => null);
}

/* 种子页：加载一次后复用（省掉每次 3~5s 的页面启动），失效则自动重建 */
let _seedPage = null;
let _seedLock = Promise.resolve();

function seedReady(page) {
  return evalT(page, () => !!(window.YT && window.YT.Client && typeof window.YT.Client.post === "function"), 4000);
}

async function getSeedPage(browser) {
  if (_seedPage && !_seedPage.isClosed()) {
    if (await seedReady(_seedPage)) return _seedPage;
    try { await _seedPage.close(); } catch (e) {}
    _seedPage = null;
  }
  const page = await browser.newPage();
  await page.setUserAgent(JSB_APP_UA);
  await page.setExtraHTTPHeaders({ "Accept-Language": "zh-CN,zh;q=0.9" });
  try { await page.goto(JSB_SEED_URL, { waitUntil: "domcontentloaded", timeout: 15000 }); } catch (e) { /* 超时继续轮询库就绪 */ }
  for (let i = 0; i < 20; i++) {
    if (await seedReady(page)) { _seedPage = page; return page; }
    await sleep(500);
  }
  try { await page.close(); } catch (e) {}
  return null;
}

/* 在页面上下文里调业务接口：加密/公钥/解密都由页面自身完成，这里只取回调对象 */
async function callApi(page, path, params, ms = 12000) {
  const r = await Promise.race([
    page.evaluate(({ base, path, params, cbMs }) => new Promise((resolve) => {
      let done = false;
      const fin = (v) => { if (!done) { done = true; resolve(v); } };
      setTimeout(() => fin({ ok: false, err: "callback-timeout" }), cbMs);
      try {
        window.YT.ajaxData(base + path, params, (res) => {
          let o = res;
          if (typeof o === "string") { try { o = JSON.parse(o); } catch (e) { /* 保留原串 */ } }
          fin({ ok: true, data: o });
        }, (e) => fin({ ok: false, err: String((e && (e.message || e.msg || e.errMsg)) || e) }));
      } catch (e) {
        fin({ ok: false, err: String((e && e.message) || e) });
      }
    }), { base: JSB_API_BASE, path, params, cbMs: Math.max(ms - 3000, 6000) }),
    sleep(ms + 1000).then(() => ({ ok: false, err: "evaluate-timeout" })),
  ]).catch(() => ({ ok: false, err: "evaluate-throw" }));
  return r || { ok: false, err: "no-result" };
}

const JSB_RISK = { "1": ["R1", "低风险"], "2": ["R2", "中低风险"], "3": ["R3", "中风险"], "4": ["R4", "中高风险"], "5": ["R5", "高风险"] };

function jsbDate(s) {
  if (!s) return null;
  const m = String(s).match(/^(\d{4})(\d{2})(\d{2})$/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  return null;
}

// 把抓取到的详情 + 净值序列映射到目标结构
function mapJsb(detail, series, navInfo) {
  const info = (detail && detail.iFinancesPrdDetailMBInfo && detail.iFinancesPrdDetailMBInfo[0]) || {};
  const riskKey = String(info.RISKLEVEL || "").trim();
  const risk = JSB_RISK[riskKey] || null;
  const established = jsbDate(info.ESTABDATE);
  const holdTerm = Number(info.INVESTTERM);
  const amtStart = Number(info.OFIRSTAMT || info.PFIRSTAMT || info.PAPPAMT);
  const quota = info.TOTUSELIMIT != null && info.TOTUSELIMIT !== "" ? Number(info.TOTUSELIMIT) : null;
  const nav = info.NAV != null && info.NAV !== "" ? Number(info.NAV) : (navInfo ? navInfo.nav : null);
  const navDate = jsbDate(info.NAV_DATE) || (navInfo ? navInfo.navDate : null);
  return {
    name: info.PRDNAME || null,
    productCode: info.PRDCODE || (navInfo && navInfo.prdCode) || null,
    manager: info.PRDSPONSOR || info.TANAME || "苏银理财有限责任公司",
    established,
    establishedFromSeries: false,
    holdDays: Number.isFinite(holdTerm) ? holdTerm : null,     // 每日开放=1；最低持有 N 天=N
    holdDaysDesc: info.INVESTTERMNAME || (holdTerm === 1 ? "每日开放" : null),
    risk: risk ? risk[0] : null,
    riskName: info.RISKNAME || (risk ? risk[1] : null),
    benchmark: info.INCOMERATE || info.RESULTRATE || null,
    profitType: info.PREINCOMTYPE || null,
    investType: null,
    amtStart: Number.isFinite(amtStart) ? amtStart : null,
    nav,
    navDate,
    registryCode: info.REGISTCODE || null,
    quota,                                                     // 剩余可认购额度(元) TOTUSELIMIT
    remainQuota: quota,                                        // 与其它银行同名字段，供 /api/product 额度汇总直接取数值
    quotaState: quota != null ? "available" : null,
    quotaText: quota != null ? String(quota) : null,
    quotaCurrency: "CNY",
    series,                                                    // [[YYYYMMDD, 单位净值, 累计净值], ...] 升序
    kind: "nav",
    navBasis: "series",
    partial: false,
    navNote: "江苏银行 App 端口(mbank5h5 H5)直连 YT.ajaxData，dateFlag=4 取成立以来全量净值 + 七字段 + 额度 + 登记编码",
    source: "live",
    bank: "jsb",
    navVia: "jsb-app",
    navPort: "app",
    ms: 0,
  };
}

/* 从净值接口返回里抽 [日期, 单位净值, 累计净值] */
function toSeries(list) {
  const byDate = new Map();
  for (const r of list || []) {
    const raw = r && r.ISS_DATE;
    if (!raw) continue;
    // 江苏银行上游给 8 位数字日期（20261015），统一成全局约定的 YYYY-MM-DD，
    // 否则前端 fmt.date() 会拆出 undefined-undefined，addDays/年化计算也会失效。
    const d = jsbDate(raw) || String(raw);
    const u = r.TB_VALUE != null ? Number(r.TB_VALUE) : (r.PRD_NAV != null ? Number(r.PRD_NAV) : null);
    const c = r.TOT_NAV != null ? Number(r.TOT_NAV) : (r.LB_VALUE != null ? Number(r.LB_VALUE) : null);
    if (!Number.isFinite(u)) continue;
    byDate.set(d, [d, u, Number.isFinite(c) ? c : u]);
  }
  return Array.from(byDate.values()).sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

/**
 * 按产品代码直查（★主入口：不需要分享链接）
 * @param {string} code 产品代码，如 J04946 / J09652
 * @param {{timeoutMs?:number}} opts
 */
export async function jsbAppByCode(code, opts = {}) {
  const prdCode = String(code || "").trim().toUpperCase();
  if (!prdCode) return null;
  const pptr = puppeteerCore();
  if (!pptr) return null;
  const browser = await sharedBrowser();
  if (!browser) return null;

  const t0 = Date.now();
  // 2026-10-22：45s→20s。实测热路径（种子页复用）单产品 ~1.3s、冷启动 ~13s；
  // 20s 足够覆盖冷启动 + 一次重试，超时即视为失败，不再让前端干等。
  const totalMs = opts.timeoutMs || 20000;

  const run = async () => {
    // 页面复用需要串行（同一 page 并发 evaluate 会互相干扰）
    const prev = _seedLock;
    let release;
    _seedLock = new Promise((r) => { release = r; });
    try { await prev; } catch (e) {}
    try {
      for (let attempt = 1; attempt <= 2; attempt++) {
        const page = await getSeedPage(browser);
        if (!page) return null;

        // ① 详情（失败且是「接口/会话」类错误 → 重建种子页重试一次）
        const det = await callApi(page, "H5queryFinanceDetail.do", { prdCode }, 10000);
        const info0 = det && det.ok && det.data && det.data.iFinancesPrdDetailMBInfo && det.data.iFinancesPrdDetailMBInfo[0];
        if (!info0) {
          try { await page.close(); } catch (e) {}
          if (_seedPage === page) _seedPage = null;
          if (attempt === 1 && det && !det.ok) continue;   // 会话/网络问题 → 重建后再试
          return null;                                     // 接口正常但无该产品 → 明确查无
        }

        // ② 净值：dateFlag=4 = 成立以来全量（一次拿全，无需滚动累加）
        const daily = await callApi(page, "H5queryTbprddaily.do", {
          prdCode, TACode: "Y04", prodTemplateNo: "D300", dateFlag: "4", prdattr: "4",
        }, 12000);
        let list = (daily && daily.ok && daily.data && daily.data.tbprddailyList) || [];
        let series = toSeries(list);

        // ③ 兜底：万一本产品不支持 dateFlag=4，退回 3/2/1 中拿到最多点的一份
        if (!series.length) {
          for (const df of ["3", "2", "1"]) {
            const r2 = await callApi(page, "H5queryTbprddaily.do", {
              prdCode, TACode: "Y04", prodTemplateNo: "D300", dateFlag: df, prdattr: "4",
            }, 10000);
            const s2 = toSeries((r2 && r2.ok && r2.data && r2.data.tbprddailyList) || []);
            if (s2.length > series.length) series = s2;
            if (series.length) break;
          }
        }

        const out = mapJsb(det.data, series, {
          nav: info0.NAV != null ? Number(info0.NAV) : null,
          navDate: jsbDate(info0.NAV_DATE),
          prdCode: info0.PRDCODE || prdCode,
        });
        out.productCode = out.productCode || prdCode;
        out.ms = Date.now() - t0;
        return out;
      }
      return null;
    } finally {
      release();
    }
  };

  return await Promise.race([run(), sleep(totalMs).then(() => null)]);
}

/**
 * 预热（serve.mjs 启动时后台调用）：提前拉 Chrome + 种子页，
 * 使首个江苏银行产品抓取命中热路径（~1.3s）而非冷启动（~13s）。
 */
export async function jsbWarmup() {
  try {
    const pptr = puppeteerCore();
    if (!pptr) return false;
    const browser = await sharedBrowser();
    if (!browser) return false;
    return !!(await getSeedPage(browser));
  } catch (e) {
    return false;
  }
}

/**
 * 兼容旧入口：传完整分享链接（从 URL 里解析 prdCode 后走按码直查）
 * 说明：shareCode 与产品无关（仅公共头 _currentUrl 携带），故无需再依赖分享链接本身。
 */
export async function jsbAppCapture(shareUrl, opts = {}) {
  const url = String(shareUrl || "").trim();
  if (!url) return null;
  let code = (opts && (opts.code || opts.prdCode)) || "";
  if (!code) {
    const m = url.match(/[?&#]prdCode=([^&#]+)/i) || url.match(/prdCode=([^&#]+)/i);
    if (m) code = decodeURIComponent(m[1]);
  }
  if (!code) return null;
  return await jsbAppByCode(code, opts);
}

export default { jsbAppByCode, jsbAppCapture, jsbWarmup, closeJsbBrowser };
