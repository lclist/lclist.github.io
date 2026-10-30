/* 光大银行「净值」直连抓取（仅本机 Node 用）
 *
 * 背景：光大 www.cebbank.com 的净值接口
 *   /eportal/ui?moduleId=12073&portal.url=/app/yglcAction!getLsjz.portlet&cpcode=<CODE>&jzrqStart=&jzrqEnd=
 * 走瑞数 RS5 动态令牌防护。
 *
 * 【2026-10-22 新增 web 主路径：官网静态页 + 页面自身 getLsjz】见文件中部
 *   `cebWebNav()`——/site/gsyw/dglc/148443261/index.html?cpcode=<CODE> 静态页不被 WAF 拦，
 *   真 Chrome 里调页面自己的 getLsjz() 读 window.dataList 拿全量历史净值（EW7746A 91 行、
 *   EW6210A 176 行、EW7899A 6 行，均含当日）。**这是当前 ceb web 通道的首选手段**，
 *   下方 legacy TLS 直连降级为兜底（瑞数 412 时灵时不灵）。
 *
 * 【2026-10-16 重大变化：WAF 升级为按 TLS 指纹(JA3)识别客户端】
 * 实测（同日多组对照，curl/Node legacy-TLS 412 vs Chrome 全形态 400）：
 *   ① 本机 Chrome（headless=new / headed、直连 / 走本地代理、过不过首页挑战）访问
 *      www.cebbank.com 一律 **400 硬拒**（6 字节空白，连首页都拒）——WAF 前置层按
 *      JA3 指纹把 Chrome 二进制（BoringSSL ClientHello）整体拉黑。此前「真浏览器破
 *      瑞数」方案（下方 solveWithChrome）在该策略下已死， headed 亦不免。
 *   ② 本机 Node 裸 fetch 报 ERR_SSL_UNSAFE_LEGACY_RENEGOTIATION_DISABLED——cebbank
 *      服务端用旧版不安全 TLS 重协商，Node 22 默认禁用。该错误曾被 preflight 误判为
 *      「出口 IP 被 WAF 硬拒」，触发 10 分钟全局停用 → 产品秒败（用户报「抓不到」的直接成因）。
 *   ③ 加 secureOptions: SSL_OP_LEGACY_SERVER_CONNECT（与 test_transport.js 同款）后
 *      网络层可达：请求稳定打到瑞数业务层（412 挑战页），且**服务端策略松动时直接
 *      200 返回净值 JSON**（2026-10-16 实测 EW7746A 86 行、产品名精确匹配）。
 *      瑞数侧有明显的时间性/节点性策略漂移（同代码同日 16:1x 200、16:4x 412），
 *      故主路径带有限重试兜底。
 *
 * 【当前主路径】legacy TLS 直连 + XHR 干净头 + 有限重试：
 *   200 + JSON → 解析 lsjzMap 返回；412 → 间隔重试（服务端松动时命中）；
 *   400/401/403 → 判定 IP 级硬拒，全局停用 10min；之后交编排层中国理财网兜底
 *   （用户 2026-10-10 决策：光大自营允许并经中国理财网名称兜底作为既定数据源）。
 *
 * 【备用路径·混合解（实验性，默认不启用）】
 *   本地 HTTPS 透明代理(nodeTransport 出网) + Chrome 经 DNS 映射在真域上下文执行瑞数
 *   挑战 JS 产出 pXlaX0mT0vLDP——曾稳定产出 B 且 Chrome 侧 reload 400/200 可见，
 *   但带 A+B 由 node 重放时服务端回 400（B 值不被认可，疑环境指纹/会话绑定校验），
 *   故未接入主路径。关键经验留存：预取挑战 JS 必须带本次 412 响应下发的 cookie、
 *   Accept 须为通配类型（瑞数按 Accept 分发不同版本 JS）、响应必须删 content-length
 *   （页面改写后长度不匹配会截断 HTML）。见 probe_ceb_hybrid3.mjs。
 *
 * 注：Cloudflare Workers 无 process/https，本模块整体不加载；ceb 在生产恒走中国理财网兜底。
 */
import { createRequire } from "module";
import crypto from "node:crypto";
import https from "node:https";
const require = createRequire(import.meta.url);
let puppeteerCore = null;
// 依次尝试多种方式解析 puppeteer-core（本模块由 worker.js 动态导入，
// 解析基址是 scrape/，而 puppeteer-core 装在 WorkBuddy 运行时 workspace/node_modules）。
for (const spec of [
  "puppeteer-core",
  "C:/Users/a/.workbuddy/binaries/node/workspace/node_modules/puppeteer-core",
  process.env.CEB_PUPPETEER,
].filter(Boolean)) {
  try { puppeteerCore = require(spec); break; } catch (e) { /* 试下一个 */ }
}

const HOST = "https://www.cebbank.com";
const NAV_PATH = (code, from, to) =>
  `/eportal/ui?moduleId=12073&portal.url=/app/yglcAction!getLsjz.portlet&cpcode=${encodeURIComponent(code)}&jzrqStart=${from}&jzrqEnd=${to}`;
// XHR 形态干净头（瑞数按 Accept 分发 JS：application/json 式会拿到缺定义的 XHR 版，
// */* 才是浏览器版；业务请求本身用 XHR 式 Accept 命中 JSON 分支）
const CEB_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const CEB_XHR_HEADERS = (extra = {}) => ({
  "User-Agent": CEB_UA,
  Accept: "application/json, text/javascript, */*; q=0.01",
  Referer: HOST + "/eportal/ui?moduleId=12073",
  "X-Requested-With": "XMLHttpRequest",
  ...extra,
});
const SECURE_OPTS = crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT;
const CEB_RETRY_TIMES = 3;      // 412 重试次数（服务端策略漂移窗口）
const CEB_RETRY_GAP_MS = 3000;  // 重试间隔

/* ======================= 官网静态页方案（2026-10-22 新增，web 路径主手段） =======================
 * /site/gsyw/dglc/148443261/index.html?cpcode=<CODE> 「对公理财·历史业绩」静态页：
 *   · 静态页本身**不被 WAF 拦**（裸 curl / 真 Chrome 均 200，与 /eportal/ui 端口两套策略）；
 *   · 页面自己的 getLsjz()（jQuery $.ajax + 瑞数 cookie）在真 Chrome 里能跑通——
 *     瑞数挑战由页面自身 JS 解开，我们只读结果。
 * 做法：headless Chrome 打开静态页 → 填宽日期范围 → 调页面 getLsjz() → 读 window.dataList
 *   （页面全局变量，行字段 JZRQ(YYYYMMDD) / JZ(单位净值) / TYPEINFO / UNIVERSAL_INCOME）。
 * 实测（2026-10-22）：EW7746A 91 行(2026-06-09→10-22，比中国理财网多 10-22 当天)、
 *   EW6210A 176 行(2026-01-28→10-22)、EW7899A 6 行(2026-09-16→10-16)。
 *   URL 里的 148443261 是 CMS 节点 id，cpcode 走 query——**任意产品码通用**（已三码验证）。
 * ⚠ 页面在「暂无历史业绩数据」时会把 .xilan_con 内容替换掉（输入框没了），但 getLsjz 函数
 *   与 dataList 仍在；跨产品查询用 CPCODE 校验防串数据（见 webQuery）。
 * ======================= ======================= */
const WEB_HISTORY_URL = (code) =>
  "https://www.cebbank.com/site/gsyw/dglc/148443261/index.html?cpcode=" + encodeURIComponent(code);

/** 本模块独立的共享浏览器（与 ceb_eoap / bob / jsb 各自单例，互不干扰） */
let _webBrowser = null;
async function sharedBrowser() {
  if (!puppeteerCore) return null;
  if (_webBrowser && _webBrowser.connected) return _webBrowser;
  const exe = findChrome();
  if (!exe) return null;
  _webBrowser = await puppeteerCore.launch({
    executablePath: exe,
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--lang=zh-CN", "--disable-blink-features=AutomationControlled"],
    defaultViewport: { width: 1280, height: 900 },
  });
  return _webBrowser;
}

/**
 * 会话页缓存（2026-10-23 重写）：
 *   【旧设计的 bug】单个共享页 + 全局 window.cpcode。并发抓 3 个光大产品时互相覆盖 cpcode/
 *   dataList，实测 EW1178A 拿 0 行、EW7746A 拖到 19.7s；编排层再回落到 12s 轮询超时 +
 *   45s 重导航，单产品飙到 38.3s（用户截图）。
 *   【新设计】页面池：每个 code 独占一页（该页 URL 自带 cpcode，导航一次即绑定），
 *   池上限 4 页、LRU 淘汰；跨 code 复用只发生在「同页改 cpcode」且此刻无其他等待者时。
 *   并发时各自开页互不干扰，同 code 的并发请求合并为一次（inflight 去重）。
 */
const WEB_POOL_MAX = 4;
const WEB_SESS_TTL_MS = 30 * 60 * 1000;
let _webSess = null; // 兼容旧字段：{ page, code, at, busy }
const _webPool = []; // [{ page, code, at, busy, inflight:Promise }]
const _webInflight = new Map(); // code -> Promise<rows> 合并同码并发

/** 关掉池中所有会话页 + 浏览器（重启/测试收尾用） */
async function closeWebPool() {
  const pages = _webPool.slice();
  _webPool.length = 0;
  _webSess = null;
  _webInflight.clear();
  for (const s of pages) { try { await s.page.close(); } catch (e) {} }
  try { if (_webBrowser && _webBrowser.connected) await _webBrowser.close(); } catch (e) {}
  _webBrowser = null;
}

/** dataList 行 → navs 数组（抽成函数供主路径与「重开」路径共用） */
function parseCebRows(rows) {
  return (rows || [])
    .map((row) => ({
      date: String(row.JZRQ || ""),
      nav: parseFloat(row.JZ),
      income: row.UNIVERSAL_INCOME != null ? parseFloat(row.UNIVERSAL_INCOME) : null,
      type: row.TYPEINFO != null ? String(row.TYPEINFO) : null,
    }))
    .filter((r) => /^\d{8}$/.test(r.date) && !isNaN(r.nav))
    .map((r) => ({ date: r.date.slice(0, 4) + "-" + r.date.slice(4, 6) + "-" + r.date.slice(6, 8), nav: r.nav, income: r.income, type: r.type }));
}

/** 新开一页并导航到该 code 的历史业绩页（成功返回 page，失败 null） */
async function openCebPage(code) {
  const browser = await sharedBrowser();
  if (!browser) return null;
  let page = null;
  try {
    page = await browser.newPage();
    await page.setUserAgent(CEB_UA);
    // 2026-10-23：45s→15s。实测有数据产品 domcontentloaded 后 getLsjz/$ 1-2s 内就绪（实测 8.1s 含浏览器冷启动）；
    // 无数据产品 body 直接给「暂无历史业绩数据」，同样很快。再长只是把失败拖成用户可见的卡住。
    await page.goto(WEB_HISTORY_URL(code), { waitUntil: "domcontentloaded", timeout: 15000 });
    const ok = await page
      .waitForFunction(() => typeof window.getLsjz === "function" && !!window.$, { timeout: 8000, polling: 200 })
      .then(() => true)
      .catch(() => false);
    if (!ok) { try { await page.close(); } catch (e) {} return null; }
    return page;
  } catch (e) {
    if (page) { try { await page.close(); } catch (e) {} }
    return null;
  }
}

/**
 * 取一个可用于查 code 的页（返回 { page, slot }）：
 *   1) 池中同 code 的空闲页 → 直接用（毫秒级命中，实测 3-6ms）
 *   2) 否则新开一页（导航 ~4s）
 * 池上限 WEB_POOL_MAX，LRU 淘汰。
 *
 * 注（2026-10-23）：曾试过「任意空闲页改导航复用」——实测反复 goto 同页不可靠，
 * 4 路并发下多页 15s 导航超时、成功率骤降（round1 三页 n=0）。故保持「新开页」，
 * 只在「同 code 命中池」时零成本复用（这是最常见场景：重复刷同一批产品）。
 */
async function acquirePage(code) {
  // 1) 同码空闲页直接复用（零开销命中）
  for (const s of _webPool) {
    if (s.code === code && !s.busy && !s.page.isClosed()) {
      s.busy = true; s.at = Date.now();
      return { page: s.page, slot: s };
    }
  }
  // 池满 → 关掉最久未用的空闲页
  if (_webPool.length >= WEB_POOL_MAX) {
    let victim = null;
    for (const s of _webPool) if (!s.busy && (!victim || s.at < victim.at)) victim = s;
    if (victim) {
      _webPool.splice(_webPool.indexOf(victim), 1);
      if (_webSess === victim) _webSess = null;
      try { await victim.page.close(); } catch (e) {}
    }
  }
  // 2) 新开一页
  const page = await openCebPage(code);
  if (!page) return null;
  const slot = { page, code, at: Date.now(), busy: true };
  _webPool.push(slot);
  if (!_webSess) _webSess = slot;
  return { page, slot };
}

function releasePage(page) {
  for (const s of _webPool) if (s.page === page) { s.busy = false; s.at = Date.now(); }
}

/** 页面内查询：填宽日期范围 → 调 getLsjz() → 等 dataList 落定且 CPCODE 匹配。
 *  2026-10-23：12s→8s 上限（实测命中 0.3-1.5s，8s 足够覆盖慢响应）。 */
async function webQuery(page, code) {
  return page.evaluate(async (code) => {
    // 【2026-10-23 实测关键】页面 load 时 dataList 就已由服务端渲染填好（EW7746A initialLen=91），
    // 根本不需要主动调 getLsjz() 再轮询等待——旧实现白等 8-12s。
    // 故改为：先直接读；只有空/串码时才调 getLsjz() 并短暂轮询。
    const readRows = () => {
      const d = window.dataList;
      if (Array.isArray(d) && d.length) return String((d[0] && d[0].CPCODE) || "").toUpperCase() === code ? d : null;
      return null;
    };
    let rows = readRows();
    if (rows) return rows;
    // 【快速失败】官网页面无该产品数据时，body 明确显示「暂无历史业绩数据」且 dataList 为空串。
    // 此时调 getLsjz 也是空 —— 直接返回 null，不白等（实测 D/G 份额原本要烧 10-19s）。
    const bodyTxt = (document.body ? document.body.innerText : "") || "";
    if (bodyTxt.indexOf("暂无历史业绩数据") >= 0) return "NODATA";
    try {
      window.cpcode = code;
      if (window.$) { $("#beginDate").val("2015-01-01"); $("#endDate").val("2035-12-31"); }
      window.getLsjz();
      const t0 = Date.now();
      while (Date.now() - t0 < 5000) {
        await new Promise((r) => setTimeout(r, 200));
        rows = readRows();
        if (rows) return rows;
        if ((document.body ? document.body.innerText : "").indexOf("暂无历史业绩数据") >= 0) return "NODATA";
      }
    } catch (e) { /* 查询异常 → null，由调用方重导航重试 */ }
    return null;
  }, code);
}

/**
 * 官网「历史业绩」静态页抓净值（真 Chrome 读页面已渲染的 dataList）。
 * 同 code 并发调用会被合并为一次网络往返（inflight 去重）。
 * @returns {{code,name,manager,bank,navs:Array<{date,nav,income,type}>}|null} 与 cebDirectNav 同构
 */
export async function cebWebNav(code, opts = {}) {
  const c = String(code || "").trim().toUpperCase();
  if (!c) return null;
  // 同码并发合并：4 路并发若同时刷光大，多个请求打同一页会互相污染
  const prev = _webInflight.get(c);
  if (prev) return prev;

  const p = (async () => {
    const t0 = Date.now();
    const acq = await acquirePage(c);
    if (!acq || !acq.page) { dbg("web 静态页会话打开失败 code=" + c); return null; }
    const { page } = acq;
    try {
      let rows = await webQuery(page, c).catch(() => null);
      if (rows === "NODATA") {
        dbg("web 静态页官网无该产品数据(页面明示「暂无历史业绩数据」) code=" + c + " (" + (Date.now() - t0) + "ms) -> 立即返回 null，不再兜底等 legacy 直连");
        return null;
      }
      // 快路径失败（dataList 尚未渲染/串码）→ 关掉该页重开一次，避免脏页长期污染池
      if (!rows) {
        for (const s of _webPool) if (s.page === page) _webPool.splice(_webPool.indexOf(s), 1);
        if (_webSess && _webSess.page === page) _webSess = null;
        try { await page.close(); } catch (e) {}
        const p2 = await openCebPage(c);
        if (!p2) return null;
        const slot = { page: p2, code: c, at: Date.now(), busy: true };
        _webPool.push(slot);
        if (!_webSess) _webSess = slot;
        try {
          rows = await webQuery(p2, c).catch(() => null);
          if (rows === "NODATA") return null;
          if (rows) {
            const navs2 = parseCebRows(rows);
            if (!navs2.length) return null;
            const nm2 = await p2.evaluate(() => window.cpname || "").catch(() => "") || "";
            dbg("web 静态页命中(重开) code=" + c + " n=" + navs2.length + " name=" + (nm2 || "-") + " (" + (Date.now() - t0) + "ms)");
            return { code: c, name: nm2, manager: "光大理财", bank: "ceb", navs: navs2 };
          }
        } finally { releasePage(p2); }
        return null;
      }
      const navs = parseCebRows(rows);
      if (!navs.length) return null;
      const name = await page.evaluate(() => window.cpname || "").catch(() => "") || "";
      dbg("web 静态页命中 code=" + c + " n=" + navs.length + " name=" + (name || "-") + " (" + (Date.now() - t0) + "ms)");
      return { code: c, name, manager: "光大理财", bank: "ceb", navs };
    } finally {
      releasePage(page);
    }
  })().finally(() => _webInflight.delete(c));

  _webInflight.set(c, p);
  return p;
}

/** 预热：拉起浏览器 + 打开一张种子页（serve.mjs 启动时调，避免首个产品付 ~10s 冷启动） */
export async function cebWebWarmup() {
  const acq = await openCebPage("EW6210A").then((page) => (page ? { page } : null)).catch(() => null);
  if (!acq || !acq.page) return false;
  const slot = { page: acq.page, code: "EW6210A", at: Date.now(), busy: true };
  _webPool.push(slot);
  if (!_webSess) _webSess = slot;
  releasePage(acq.page);
  return true;
}

export async function closeCebWebBrowser() {
  await closeWebPool();
}

function pad(n) { return String(n).padStart(2, "0"); }
function ymd(d) { return "" + d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()); }

// 候选 Chrome 可执行文件（按存在性挑选）
const CHROME_CANDIDATES = [
  process.env.CEB_CHROME,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "C:/Users/a/.agent-browser/browsers/chrome-154.0.8037.92/chrome.exe",
  "C:/Users/a/.agent-browser/browsers/chrome-155.0.8059.39/chrome.exe",
].filter(Boolean);
function findChrome() {
  for (const p of CHROME_CANDIDATES) {
    try { require("fs").accessSync(p); return p; } catch (e) { /* 不存在 */ }
  }
  return null;
}

// NAV_DEBUG=1 时输出失败原因分阶段日志（launch/goto/响应状态/body 形态），定位直连快败根因
function dbg(msg) {
  try { if (process.env && process.env.NAV_DEBUG) console.log("[navdebug] cebx " + msg); } catch (e) {}
}

/** 真浏览器破瑞数：加载 NAV URL，等页面变成 JSON 后返回 body 文本 */
async function solveWithChrome(url) {
  if (!puppeteerCore) { dbg("puppeteer-core 未解析到（装在 WorkBuddy 运行时 workspace）-> null"); return null; }
  const exe = findChrome();
  if (!exe) { dbg("未找到系统 Chrome -> null"); return null; }
  let browser;
  try {
    // CEB_PROXY：让 puppeteer 走数据中心出口代理（cebbank 对住宅/移动 IP 硬拒 400、
    // 仅对数据中心 IP 发 412 挑战）。设上后 B（纯直连）在用户本机可破 WAF。
    const proxy = process.env.CEB_PROXY;
    const launchArgs = [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--disable-blink-features=AutomationControlled",
    ];
    if (proxy) {
      launchArgs.push("--proxy-server=" + proxy);
      dbg("puppeteer 走代理出口 CEB_PROXY=" + proxy);
    }
    browser = await puppeteerCore.launch({
      executablePath: exe,
      headless: "new",
      args: launchArgs,
    });
    const page = await browser.newPage();
    // 反自动化检测：抹掉 webdriver 标志
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    });
    // 【A 路·补 XHR 头部】裸 page.goto 是 document 导航（Accept:text/html），光大 WAF 前置层直接 400 拒；
    // 该 portlet 实际期望 XHR（带 Referer + X-Requested-With + Accept:application/json）。补头部后
    // 期望 WAF 改发 412 瑞数挑战页，真浏览器解令牌重抓即得 JSON。
    const referer = HOST + "/eportal/ui?moduleId=12073";
    const xhrHeaders = {
      Referer: referer,
      "X-Requested-With": "XMLHttpRequest",
      Accept: "application/json, text/javascript, */*; q=0.01",
    };
    const resp = await page.goto(url, { waitUntil: "networkidle2", timeout: 30000, headers: xhrHeaders });
    if (!resp) { dbg("goto 无响应 -> null"); return null; }
    dbg("goto status=" + resp.status() + " (已带 XHR 头部)");
    // 瑞数可能在首跳后自动重抓；等 body 变成 JSON
    await page
      .waitForFunction(
        () => {
          const t = (document.body && document.body.innerText) || "";
          const s = t.trim();
          return s.startsWith("{") || s.startsWith("[");
        },
        { timeout: 20000 }
      )
      .catch(() => {});
    const txt = await page.evaluate(() => document.body.innerText);
    if (!txt || !(txt.trim().startsWith("{") || txt.trim().startsWith("["))) {
      dbg("body 未变成 JSON（瑞数挑战未过/WAF 拦截），head=" + JSON.stringify((txt || "").trim().slice(0, 80)));
    }
    return txt || null;
  } catch (e) {
    dbg("launch/goto throw " + ((e && e.message) || e));
    return null;
  } finally {
    if (browser) { try { await browser.close(); } catch (e) {} }
  }
}

/**
 * 会话级「ceb 直连全局停用」标志。
 * 光大 WAF 对出口 IP 做风险分层：住宅 IP 直 400 硬拒、云/机房出口才给 412 瑞数挑战页
 * （沙箱 curl 三组请求头均 412 已证实）。该拒是 IP/会话级而非单码级——任一码 400 即代表
 * 整条 ceb 直连在本会话不可用，故用【全局标志】短路，避免每个不同码都烧 ~25s puppeteer
 * 才回落中国理财网/工行。首次失败后 10 分钟内所有 ceb 直连直接返回 null（毫秒级）。
 */
let _cebDirectDownUntil = 0; // 全局过期时间戳(ms)；>now 表示本会话 ceb 直连停用
const CEB_FAIL_TTL = 10 * 60 * 1000; // 10 分钟

/**
 * legacy TLS GET（自包含，不依赖 test_transport.js）。
 * cebbank 服务端用旧版不安全 TLS 重协商，Node 22 裸 fetch 直接
 * ERR_SSL_UNSAFE_LEGACY_RENEGOTIATION_DISABLED；加 SSL_OP_LEGACY_SERVER_CONNECT 即通
 * （与 test_transport.js 同款修法，本模块需独立可加载故内嵌）。
 * @returns {Promise<{status:number, body:string, setCookie:string[]}>} 网络异常时 reject
 */
function cebHttpsGet(path, extraHeaders = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "www.cebbank.com",
        port: 443,
        path,
        method: "GET",
        headers: CEB_XHR_HEADERS(extraHeaders),
        secureOptions: SECURE_OPTS,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          const sc = res.headers["set-cookie"];
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
            setCookie: sc ? (Array.isArray(sc) ? sc.slice() : [sc]) : [],
          });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("cebbank request timeout")));
    req.end();
  });
}

/**
 * 【轻量预判】在重试之前先用一次 legacy TLS 探测判断出口 IP 是否被 WAF 硬拒：
 * 400/401/403 = IP 级硬拒（实测住宅/移动 IP 形态）；412 = 瑞数挑战（业务层可达，
 *   走重试等松动窗口）；200 = 直接放行。网络异常按不可用处理。
 */
async function cebPreflightDown(code, from, to) {
  const path = NAV_PATH(code, from, to);
  try {
    const r = await cebHttpsGet(path, {}, 10000);
    dbg("preflight ceb portlet -> " + r.status + " (legacy TLS)");
    if (r.status === 400 || r.status === 401 || r.status === 403) {
      dbg("preflight ceb portlet -> " + r.status + " (出口 IP 被 WAF 硬拒) -> 判定整条 ceb 直连本会话不可用");
      return true;
    }
    dbg("preflight ceb portlet -> " + r.status + " (非 IP 硬拒，走主路径)");
    return false;
  } catch (e) {
    dbg("preflight ceb portlet -> 异常(" + ((e && e.message) || e) + ") -> 判定不可用");
    return true;
  }
}

/**
 * 直连抓取光大某产品净值。
 * @returns {{code,name,manager,bank,navs:Array<{date,nav,income,type}>}|null}
 */
export async function cebDirectNav(code, opts = {}) {
  if (_cebDirectDownUntil > Date.now()) {
    dbg("ceb 直连全局停用中(距恢复 " + Math.round((_cebDirectDownUntil - Date.now()) / 1000) + "s) -> 跳过 code=" + code);
    return null;
  }
  const to = opts.end || ymd(new Date());
  const from = opts.start || "20200101";
  const path = NAV_PATH(code, from, to);

  // 【轻量预判】IP 硬拒(400/401/403)或网络异常时直接全局停用，不烧重试。
  // 注：2026-10-16 起 preflight 走 legacy TLS，不再把「Node 裸 fetch 的 TLS 策略错误」
  // 误判成 IP 硬拒（那曾导致 10 分钟秒败，是「抓不到」的直接成因）。
  const forceDirect = !!(process.env && process.env.CEB_FORCE_DIRECT);
  if (!forceDirect) {
    if (await cebPreflightDown(code, from, to)) {
      _cebDirectDownUntil = Date.now() + CEB_FAIL_TTL;
      dbg("ceb 直连失败(出口 IP 被 WAF 硬拒) -> 全局停用 " + (CEB_FAIL_TTL / 60000) + "min，后续同会话直接回落");
      return null;
    }
  } else {
    dbg("CEB_FORCE_DIRECT=1 -> 跳过预判，强制 legacy TLS 直连");
  }

  // 【主路径】legacy TLS 直连 + 有限重试。
  // 瑞数策略有明显的时间性/节点性漂移（同日实测 16:1x 直接 200 出 JSON、16:4x 持续 412），
  // 故 412 时按间隔重试若干次，赌松动窗口；400 才是 IP 级硬拒（停用）。
  for (let attempt = 1; attempt <= CEB_RETRY_TIMES; attempt++) {
    let r;
    try {
      r = await cebHttpsGet(path);
    } catch (e) {
      dbg("ceb legacy get throw " + ((e && e.message) || e) + " attempt=" + attempt + " -> 全局停用");
      _cebDirectDownUntil = Date.now() + CEB_FAIL_TTL;
      return null;
    }
    if (r.status === 200) {
      let json;
      try { json = JSON.parse(r.body.trim()); } catch (e) {
        dbg("ceb 200 但非 JSON code=" + code + " head=" + JSON.stringify(r.body.slice(0, 60)));
        return null; // 200 而body非JSON=异常页，重试无益
      }
      const map = json.lsjzMap || json.data || (Array.isArray(json) ? json : null);
      if (!map || !map.length) {
        dbg("ceb 200 JSON 但无净值行 code=" + code + " -> 视为无数据(不重试)");
        return null;
      }
      const navs = map
        .map((row) => ({
          date: row.JZRQ || row.jzrq || row.date,
          nav: parseFloat(row.JZ ?? row.nav ?? row.jz),
          income: row.UNIVERSAL_INCOME ?? row.income ?? null,
          type: row.TYPEINFO ?? row.type ?? null,
        }))
        .filter((row) => row.date && !isNaN(row.nav));
      if (!navs.length) return null;
      dbg("ceb legacy 直连命中 code=" + code + " n=" + navs.length + " name=" + (json.cpname || json.name || "-") + " attempt=" + attempt);
      return {
        code,
        name: json.cpname || json.name || "",
        manager: "光大理财",
        bank: "ceb",
        navs,
      };
    }
    if (r.status === 400 || r.status === 401 || r.status === 403) {
      dbg("ceb portlet -> " + r.status + " (IP 硬拒) -> 全局停用");
      _cebDirectDownUntil = Date.now() + CEB_FAIL_TTL;
      return null;
    }
    dbg("ceb portlet -> " + r.status + " attempt=" + attempt + "/" + CEB_RETRY_TIMES + " code=" + code);
    if (attempt < CEB_RETRY_TIMES) {
      await new Promise((res) => setTimeout(res, CEB_RETRY_GAP_MS));
    }
  }
  dbg("ceb 持续 412（瑞数挑战，未遇松动窗口）-> 交编排层中国理财网兜底 code=" + code);
  return null;
}

/* ======================= 历史：jsdom 破瑞数（已弃用，WAF 400 拒） =======================
 * 早期版本用 jsdom 执行挑战脚本派生 pXlaX0mT0vLDP cookie 后重抓，EW7746A 曾成功抓到 80 条。
 * 但 RS5 引擎升级（berrCCR8OusE.1058d2a.js）后，jsdom 在无头/无 GPU 环境算出的 P-cookie
 * 被 WAF 以 400（6 字节空响应）拒绝，且连此前成功的 EW7746A 也一并失败 → 判定为 WAF 对
 * 非真机指纹/算力的校验，弃用，改走上面的真浏览器方案。保留 proto 于 _ceb_rs_jsdom.mjs。
 */
