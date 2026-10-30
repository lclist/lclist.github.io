/* ==========================================================================
 * 江苏银行 App 端口（纯 JS 直连版）—— ★ 不依赖 Chrome，Node 与 Cloudflare Workers 双端可用
 * ==========================================================================
 *
 * 【为什么重写】
 *   原实现 jsb_app.mjs 靠「本机 Chrome + puppeteer-core」在页面上下文里调
 *   `window.YT.ajaxData`，由页面自己完成加解密。Cloudflare Workers 没有 Chrome、
 *   没有文件系统 → `puppeteerCore()` 返回 null → 该腿恒失败（2026-10-29 定位）。
 *   本模块把江苏银行【官方加密模块】移植进纯 JS，用 fetch + 官方加解密函数直接
 *   发业务请求，Workers 也能抓。
 *
 * 【协议（2026-10-29 逆向自真实抓包）】
 *   ① getkey.do（明文 JSON）
 *      POST https://mbank5h5.jsbchina.cn/mbank/getkey.do
 *      → {"head":{...},"body":{"publicKey":"04<130 hex>"}}   ← 65 字节**椭圆曲线**公钥（P-256 类）
 *      ⚠ 不是 RSA —— 旧注释写「RSA」是错的。
 *   ② 业务请求（POST application/json）
 *      URL : https://mbank5h5.jsbchina.cn/mbank//finance/<接口>.do
 *      Body: {"head":{H_CHNL_ID:"1020",H_TIME:<ms>,H_TIME_OFFSET:"0",H_NONCE:<uuid v4>},
 *             "body":"<md5>\u001d<aes>\u001d<rsa>"}
 *      明文 = JSON.stringify({...业务参数,
 *             _currentSource:"H5", _currentUrl:"page/home/fina/main.html",
 *             REQ_TIME:"yyyyMMddHHmmssSSS"})
 *      三段（以 \u001d / 0x1F 分隔）：
 *        ① jsbankMD5(明文)                 —— 64 hex（★官方是 32 字节自定义变体，非标准 MD5）
 *        ② jsbankAES.encrypt(明文, key)    —— 官方「AES」是 InvMixColumns 密钥编排变体，
 *                                            **不是标准 AES**，故必须用官方实现，勿自行替换
 *        ③ jsbankRSA.doEncrypt(key, 公钥,0) —— 官方自定义 EC 流密码：
 *                                            临时密钥对 → 共享点 → 哈希密钥流 XOR → 附 MAC
 *   ③ 响应
 *      {"head":{H_STATUS:"1",H_MSG:"交易成功",...},"body":"<aes 密文 hex>"}
 *      → jsbankAES.decrypt(body, 同一个 key) → 明文 JSON
 *
 * 【关键参数】
 *   key = 32 位 [0-9A-Za-z] 随机串（官方 SecurityJSBANK.getkey() = randomString(32)）
 *        ※ 官方 jsbankAES 用「十六进制两两解析」把 key 字符串折成 16 字节，
 *          非十六进制字符会被当成 0 —— 服务端用同一套规则派生，故自洽，无需改动。
 *   公钥每 10 分钟刷新一次（服务端可能轮换密钥对）；失败时自动重取一次。
 * ========================================================================== */

/* ⚠ 加密模块必须【懒加载】，不能静态 import（2026-10-29 修 Worker 部署 10021 报错）：
 *   jsbankRSA.gen.mjs 是官方 webpack 打包产物，其模块顶层会自调用
 *   `generateEcparam()` → `generateKeyPairHex()`，而后者内部用 `crypto.subtle.generateKey`
 *   —— **异步**。Cloudflare Workers 明令禁止在【全局作用域】做异步 I/O / 生成随机值，
 *   一旦被 esbuild 静态打进 bundle 就会在 Worker 启动期报
 *   「Disallowed operation called within global scope … [code: 10021]」→ 部署直接失败。
 *   之前线上没事是因为 jsb_nav.mjs 从未被打进 bundle（jsb_worker.mjs 只取 jsbMap/jsbToSeries，
 *   而 Worker 侧走 Browser Rendering 页面内 YT.ajaxData，不需要本文件的加解密能力）。
 *   ⇒ 改成「用到时才 import」：模块顶层不再求值，纯 JS 直连路径在首次调用时加载。
 *   ⚠ 必须用【静态可分析的 import() 字面量路径】，否则 esbuild 无法打包、Worker 运行时报错。
 */
let _cryptoReady = null;
async function ensureCrypto() {
  if (!_cryptoReady) {
    _cryptoReady = (async () => {
      await import("./jsb_crypto/_shim.mjs");   // 必须最先：给 Workers 补 window（见垫片文件说明）
      await import("./jsb_crypto/jsbankAES.gen.mjs");
      await import("./jsb_crypto/jsbankRSA.gen.mjs");
      await import("./jsb_crypto/jsbankMD5.gen.mjs");
      return true;
    })().catch((e) => { _cryptoReady = null; throw e; });
  }
  return _cryptoReady;
}

const G = globalThis;

const JSB_HOST = "https://mbank5h5.jsbchina.cn";
const JSB_API_BASE = JSB_HOST + "/mbank//finance/";
const JSB_GETKEY_URL = JSB_HOST + "/mbank/getkey.do";
const JSB_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.40(0x1800282a) NetType/WIFI Language/zh_CN";
const SEP = String.fromCharCode(29); // 0x1F 分段符
const CHNL_ID = "1020";
const CURRENT_URL = "page/home/fina/main.html"; // 官方页面里的 YT.NavUtil.getCurrenetUrl()
const TIME_OFFSET = "0";
const PUBKEY_TTL_MS = 10 * 60 * 1000;

/* ------------------------------ 小工具 ------------------------------ */

function pad(n, w = 2) { return String(n).padStart(w, "0"); }

/** REQ_TIME = yyyyMMddHHmmssSSS（官方用「本地时区」；服务端在东八区，故统一按 UTC+8 生成） */
export function jsbReqTime(d = new Date()) {
  const bj = new Date(d.getTime() + 8 * 3600 * 1000);
  return `${bj.getUTCFullYear()}${pad(bj.getUTCMonth() + 1)}${pad(bj.getUTCDate())}` +
    `${pad(bj.getUTCHours())}${pad(bj.getUTCMinutes())}${pad(bj.getUTCSeconds())}${pad(bj.getUTCMilliseconds(), 3)}`;
}

/** 官方 SecurityJSBANK.randomString(32)：[0-9A-Za-z] 随机串 */
export function jsbRandomKey(len = 32) {
  const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const buf = new Uint8Array(len);
  G.crypto.getRandomValues(buf);
  let s = "";
  for (let i = 0; i < len; i++) s += chars[buf[i] % chars.length];
  return s;
}

function jsbGuid() {
  if (G.crypto && typeof G.crypto.randomUUID === "function") return G.crypto.randomUUID();
  const b = new Uint8Array(16); G.crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => pad(x.toString(16)));
  return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${h.slice(6, 8).join("")}-${h.slice(8, 10).join("")}-${h.slice(10, 16).join("")}`;
}

/* --------------------------- 公钥获取（带缓存） --------------------------- */

let _pubCache = { key: null, at: 0 };

export async function jsbGetPublicKey(opts = {}) {
  const now = Date.now();
  if (!opts.force && _pubCache.key && now - _pubCache.at < PUBKEY_TTL_MS) return _pubCache.key;
  const headers = {
    "User-Agent": JSB_UA,
    "Accept": "*/*",
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Referer": JSB_HOST + "/mbank/page/indexJsb.html",
  };
  if (opts.cookie) headers.Cookie = opts.cookie;
  const res = await fetch(JSB_GETKEY_URL, {
    method: "POST",
    headers,
    body: "",
  });
  if (!res.ok) throw new Error("getkey HTTP " + res.status);
  const j = JSON.parse(await res.text());
  const pk = j && j.body && j.body.publicKey;
  if (!pk) throw new Error("getkey 未返回 publicKey: " + JSON.stringify(j).slice(0, 200));
  _pubCache = { key: pk, at: Date.now() };
  return pk;
}

/* ------------------------------ 业务请求 ------------------------------ */

/**
 * 发一条加密业务请求并解密响应。
 * @param {string} path 接口名，如 "H5queryFinanceDetail.do"
 * @param {object} params 业务参数（如 {prdCode:"J04946"}）
 * @param {object} opts {timeoutMs, publicKey}
 */
export async function jsbCall(path, params, opts = {}) {
  await ensureCrypto();   // 懒加载官方加密模块（见文件头说明：避免 Worker 全局作用域 10021）
  const timeoutMs = opts.timeoutMs || 15000;
  const publicKey = opts.publicKey || (await jsbGetPublicKey(opts));
  const key = jsbRandomKey(32);

  // 明文：官方链路是 params → 追加 _currentSource/_currentUrl → 再追加 REQ_TIME
  const plainObj = Object.assign({}, params, {
    _currentSource: "H5",
    _currentUrl: CURRENT_URL,
    REQ_TIME: jsbReqTime(),
  });
  const plain = JSON.stringify(plainObj);

  const body = [
    G.jsbankMD5(plain),
    G.jsbankAES.encrypt(plain, key),
    G.jsbankRSA.doEncrypt(key, publicKey, 0),
  ].join(SEP);

  const head = {
    H_CHNL_ID: CHNL_ID,
    H_TIME: String(Date.now()),
    H_TIME_OFFSET: TIME_OFFSET,
    H_NONCE: jsbGuid(),
  };

  const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null;
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": JSB_UA,
    "Accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9",
    "Referer": JSB_HOST + "/mbank/page/indexJsb.html",
  };
  if (opts.cookie) headers.Cookie = opts.cookie;
  let res, text;
  try {
    res = await fetch(JSB_API_BASE + path, {
      method: "POST",
      headers,
      body: JSON.stringify({ head, body }),
      signal: ctl ? ctl.signal : undefined,
    });
    text = await res.text();
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (!res.ok) throw new Error(path + " HTTP " + res.status + " " + text.slice(0, 200));
  let j;
  try { j = JSON.parse(text); } catch (e) { throw new Error(path + " 响应非 JSON: " + text.slice(0, 200)); }
  if (!j.head || j.head.H_STATUS !== "1") {
    throw new Error(path + " 交易失败: " + ((j.head && (j.head.H_MSG || j.head.H_STATUS)) || text.slice(0, 200)));
  }
  const decrypted = G.jsbankAES.decrypt(j.body, key);
  try { return JSON.parse(decrypted); } catch (e) { return decrypted; }
}

/* --------------------------- 详情 / 净值映射 --------------------------- */

const JSB_RISK = { "1": ["R1", "低风险"], "2": ["R2", "中低风险"], "3": ["R3", "中风险"], "4": ["R4", "中高风险"], "5": ["R5", "高风险"] };

function jsbDate(s) {
  if (!s) return null;
  const m = String(s).match(/^(\d{4})(\d{2})(\d{2})$/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

export function jsbToSeries(list) {
  const byDate = new Map();
  for (const r of list || []) {
    const raw = r && r.ISS_DATE;
    if (!raw) continue;
    const d = jsbDate(raw) || String(raw);
    const u = r.TB_VALUE != null ? Number(r.TB_VALUE) : (r.PRD_NAV != null ? Number(r.PRD_NAV) : null);
    const c = r.TOT_NAV != null ? Number(r.TOT_NAV) : (r.LB_VALUE != null ? Number(r.LB_VALUE) : null);
    if (!Number.isFinite(u)) continue;
    byDate.set(d, [d, u, Number.isFinite(c) ? c : u]);
  }
  return Array.from(byDate.values()).sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

export function jsbMap(detail, series, navInfo) {
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
    manager: info.PRDSPONSOR || info.TANAME || null,
    established,
    establishedFromSeries: false,
    holdDays: Number.isFinite(holdTerm) ? holdTerm : null,
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
    quota,
    remainQuota: quota,
    quotaState: quota != null ? "available" : null,
    quotaText: quota != null ? String(quota) : null,
    quotaCurrency: "CNY",
    series,
    kind: "nav",
    navBasis: "series",
    partial: false,
    navNote: "江苏银行 App 端口（纯 JS 直连官方 jsbankAES/jsbankRSA/jsbankMD5 加解密，dateFlag=4 成立以来全量净值 + 七字段 + 额度 + 登记编码；无需 Chrome，Workers 可用）",
    source: "live",
    bank: "jsb",
    navVia: "jsb-app",
    navPort: "app",
    ms: 0,
  };
}

/* ------------------------------ 主入口 ------------------------------ */

/**
 * 按产品代码直查江苏银行产品（详情 + 成立以来全量净值 + 额度 + 登记编码）
 * @param {string} code 产品代码，如 J04946 / J09652
 */
export async function jsbNavByCode(code, opts = {}) {
  const prdCode = String(code || "").trim().toUpperCase();
  if (!prdCode) return null;
  const t0 = Date.now();

  const run = async () => {
    const publicKey = await jsbGetPublicKey(opts);
    // 详情
    const det = await jsbCall("H5queryFinanceDetail.do", { prdCode }, { ...opts, publicKey });
    const info0 = det && det.iFinancesPrdDetailMBInfo && det.iFinancesPrdDetailMBInfo[0];
    if (!info0) return null;

    // 净值：dateFlag=4 = 成立以来全量
    let series = [];
    try {
      const daily = await jsbCall("H5queryTbprddaily.do", {
        prdCode, TACode: "Y04", prodTemplateNo: "D300", dateFlag: "4", prdattr: "4",
      }, { ...opts, publicKey });
      series = jsbToSeries(daily && daily.tbprddailyList);
    } catch (e) { /* 净值失败不致命，详情仍可用 */ }

    // 兜底：dateFlag=4 拿不到就退回 3/2/1 取点最多的
    if (!series.length) {
      for (const df of ["3", "2", "1"]) {
        try {
          const r2 = await jsbCall("H5queryTbprddaily.do", {
            prdCode, TACode: "Y04", prodTemplateNo: "D300", dateFlag: df, prdattr: "4",
          }, { ...opts, publicKey });
          const s2 = jsbToSeries(r2 && r2.tbprddailyList);
          if (s2.length > series.length) series = s2;
          if (series.length) break;
        } catch (e) { /* ignore */ }
      }
    }

    const out = jsbMap(det, series, {
      nav: info0.NAV != null ? Number(info0.NAV) : null,
      navDate: jsbDate(info0.NAV_DATE),
      prdCode: info0.PRDCODE || prdCode,
    });
    out.productCode = out.productCode || prdCode;
    out.ms = Date.now() - t0;
    return out;
  };

  const totalMs = opts.timeoutMs || 20000;
  let timer = null;
  try {
    return await Promise.race([
      run(),
      new Promise((r) => { timer = setTimeout(() => r(null), totalMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** 只取净值序列（轻量） */
export async function jsbNavSeries(code, opts = {}) {
  const prdCode = String(code || "").trim().toUpperCase();
  if (!prdCode) return [];
  const publicKey = await jsbGetPublicKey(opts);
  const daily = await jsbCall("H5queryTbprddaily.do", {
    prdCode, TACode: "Y04", prodTemplateNo: "D300", dateFlag: "4", prdattr: "4",
  }, { ...opts, publicKey });
  return jsbToSeries(daily && daily.tbprddailyList);
}

export default { jsbNavByCode, jsbNavSeries, jsbCall, jsbGetPublicKey, jsbRandomKey, jsbReqTime, jsbMap, jsbToSeries };
