/* 把江苏银行官方加密模块（jsbankAES / jsbankRSA / jsbankMD5）转成 Worker 可用的 ESM。
 *
 * 为什么需要转：原文件是「浏览器全局脚本」写法 —— 顶层用未声明赋值 `jsbankAES=...`
 * 建全局变量，还引用 `window.crypto` / `navigator.*`。ESM 是严格模式，未声明赋值会抛
 * ReferenceError；Cloudflare Workers 也没有 `window`。故做两处等价改写：
 *   ① 顶层赋值 → `globalThis.xxx = ...`（语义不变，仍是全局对象上的同名属性）
 *   ② `window.` → `globalThis.`、`typeof window` → `typeof globalThis`（Workers/Node 都成立）
 *
 * 原始文件来自江苏银行手机银行 H5（mbank5h5.jsbchina.cn），随 src/ 一并留档，勿手改。
 * 用法：node _gen.cjs
 */
const fs = require("node:fs");
const path = require("node:path");

const DIR = __dirname;
const SRC = path.join(DIR, "src");

/* 顶层未声明赋值的变量名（= function 形式） */
const TOP_ASSIGN = {
  "jsbankAES.js": ["jsbankAES", "fromCodePoint", "encryptAES", "decryptAES"],
  "jsbankRSA.js": ["jsbankRSA", "generateKeyPairHex", "doEncrypt", "doDecrypt", "doSignature", "doVerifySignature", "getPoint"],
  "jsbankMD5.js": ["jsbankMD5", "constructJsbankMD5"],
};

const SRC_URL = {
  "jsbankAES.js": "https://mbank5h5.jsbchina.cn/mbank/assets/js/security/jsbank/jsbankAES.js",
  "jsbankRSA.js": "https://mbank5h5.jsbchina.cn/mbank/assets/js/security/jsbank/jsbankRSA.js",
  "jsbankMD5.js": "https://mbank5h5.jsbchina.cn/mbank/assets/js/security/jsbank/jsbankMD5.js",
};

function transform(name, text) {
  let out = text;
  // ② window → globalThis（Workers 无 window；Node 无 window 但有 globalThis）
  out = out.replace(/\btypeof window\b/g, "typeof globalThis");
  out = out.replace(/\bwindow\./g, "globalThis.");
  // ① 顶层未声明赋值 → globalThis.xxx = ...
  for (const id of TOP_ASSIGN[name] || []) {
    // 行首（含空白）出现的 `id =` / `id=`
    const re = new RegExp("(^|\\n)(\\s*)" + id + "(\\s*=\\s*function)", "g");
    out = out.replace(re, (m, p1, p2, p3) => `${p1}${p2}globalThis.${id}${p3}`);
  }
  return out;
}

for (const name of Object.keys(TOP_ASSIGN)) {
  const srcFile = path.join(SRC, name);
  const raw = fs.readFileSync(srcFile, "utf8");
  const gen = transform(name, raw);
  const header = `/* 由 _gen.cjs 自动生成，请勿手改。\n * 来源：${SRC_URL[name]}\n * 改动：顶层未声明赋值 → globalThis.xxx；window. → globalThis.\n */\n`;
  const outFile = path.join(DIR, name.replace(/\.js$/, ".gen.mjs"));
  fs.writeFileSync(outFile, header + gen, "utf8");
  console.log("生成", path.relative(DIR, outFile), fs.statSync(outFile).size, "bytes");
}
