/* 江苏银行官方加密模块在 Cloudflare Workers 运行时的环境垫片。
 *
 * ⚠️ 必须在 jsbankAES/jsbankRSA/jsbankMD5 之前 import（ESM 导入求值顺序 = 书写顺序）。
 *
 * 官方 jsbankRSA.js 里有两处环境探测：
 *   ① `var fi = "undefined"!=typeof navigator`  → 有 typeof 守卫，安全（Workers 无 navigator 也安全）
 *   ② `if("undefined"!=typeof window && window.crypto)` → Workers 里 window 不存在，
 *      会退化到 `Math.random()` 取随机数（临时 EC 密钥的熵变弱）。
 *      补一个 window = globalThis，就能用上 Workers 原生的 crypto.getRandomValues。
 *
 * 只在「像 Workers 的环境」补 window：本项目本机（Node）有 process，
 * 造一个 window 反而可能干扰本项目其它地方对浏览器/Node 的判定。
 */
const isWorkerLike =
  (typeof process === "undefined") ||
  (typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers");

if (isWorkerLike && typeof globalThis.window === "undefined") {
  try {
    Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true, writable: true });
  } catch (e) { /* 定义失败不影响功能，只是随机数来源退化 */ }
}
