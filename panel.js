/* 产品管理面板共享行为（index.html 与 manage.html 共用，单一来源）
 * 仅抽取「滚动 / 横杆 / 尺寸」这类最容易出 bug 的面板行为；
 * loadManage / pushLayer / doCloseEdit 等仍由各页在本作用域内提供，经 Panel.init 注入。
 * 依赖：面板 DOM（#manageMask / #mgScroll / #mgTableWrap / #mgHDock）已存在于文档。
 * 本文件为经典脚本（非 module），加载即定义 window.Panel；#mgHDock 挂接延迟到 DOMContentLoaded，
 * 以便 panel.js 可放在 <head> 或任意位置而无需关心面板标记是否已解析。
 */
(function () {
  "use strict";

  var deps = {};

  /* 把 #mgTableWrap 高度设为 .mg-scroll 可视高度：滚动行程恰 = 银行卡片(hero)高度，
     拉到底卡片整块滚出、表格底对齐视口底，与主页行为一致。 */
  function sizeMgScroll() {
    var sc = document.getElementById("mgScroll");
    var tw = document.getElementById("mgTableWrap");
    if (!sc || !tw) return;
    tw.style.height = sc.clientHeight + "px";
  }
  function mgScrollResize() {
    var mask = document.getElementById("manageMask");
    if (!mask || mask.classList.contains("hidden")) return;
    sizeMgScroll();
  }

  function open() {
    return Promise.resolve(deps.loadManage ? deps.loadManage() : null).then(function () {
      var mask = document.getElementById("manageMask");
      if (mask) mask.classList.remove("hidden");
      /* 锁背景滚动：全屏面板自带 .mg-scroll 滚动杆（蓝色），背景主页不再提供滚动，
         避免「拉全局纵向杆实际滚的是面板背后主页」的问题（银行卡片因此滚不出视线）。 */
      document.documentElement.style.overflow = "hidden";
      document.body.style.overflow = "hidden";
      sizeMgScroll();
      requestAnimationFrame(sizeMgScroll);
      window.addEventListener("resize", mgScrollResize);
      if (window.mgHDockSync) setTimeout(window.mgHDockSync, 0);   /* 面板横向杆：打开后立即同步宽度/可见性 */
      if (deps.pushLayer) deps.pushLayer("manage");
    });
  }
  function close() {
    var mask = document.getElementById("manageMask");
    if (mask) mask.classList.add("hidden");
    if (deps.doCloseEdit) deps.doCloseEdit();
    window.removeEventListener("resize", mgScrollResize);
    document.documentElement.style.overflow = "";
    document.body.style.overflow = "";
  }

  /* 各页在自身作用域内调用，注入页面私有依赖；同时把 open/close 挂到 window，
     兼容既有调用方 window.openManage() / window.closeManage()。 */
  function init(opts) {
    deps = opts || {};
    window.openManage = open;
    window.closeManage = close;
    expose();
  }

  function expose() {
    window.Panel = window.Panel || {};
    window.Panel.init = init;
    window.Panel.open = open;
    window.Panel.close = close;
    window.Panel.sizeMgScroll = sizeMgScroll;
    window.Panel.mgScrollResize = mgScrollResize;
  }

  /* ---------- 面板横向滚动杆 #mgHDock（与主页 #hDock 同款，纯 DOM） ---------- */
  function setupMgHDock() {
    var dock = document.getElementById("mgHDock");
    var wrap = document.getElementById("mgTableWrap");
    var mask = document.getElementById("manageMask");
    if (!dock || !wrap || !mask) return;
    var spacer = dock.firstElementChild;
    var lock = false;
    var desktop = window.matchMedia("(min-width: 760px)");

    function syncWidth() {
      if (!desktop.matches || mask.classList.contains("hidden")) { dock.classList.remove("on"); return; }
      if (wrap.scrollWidth - wrap.clientWidth <= 1) { dock.classList.remove("on"); return; }
      dock.classList.add("on");
      /* dock 比表格可视区宽出「表格纵向滚动杆」那 14px，补上差值后两边滚动范围才一致 */
      spacer.style.width = (wrap.scrollWidth - wrap.clientWidth + dock.clientWidth) + "px";
      dock.scrollLeft = wrap.scrollLeft;
    }
    dock.addEventListener("scroll", function () {
      if (lock) return; lock = true;
      wrap.scrollLeft = dock.scrollLeft;
      lock = false;
    });
    wrap.addEventListener("scroll", function () {
      if (lock) return; lock = true;
      dock.scrollLeft = wrap.scrollLeft;
      lock = false;
    });
    window.addEventListener("resize", syncWidth);
    if (desktop.addEventListener) desktop.addEventListener("change", syncWidth);
    if (window.ResizeObserver) { try { new ResizeObserver(syncWidth).observe(wrap); } catch (e) {} }
    try { new MutationObserver(syncWidth).observe(wrap, { childList: true, subtree: true }); } catch (e) {}
    window.mgHDockSync = syncWidth;
    syncWidth();
  }

  /* panel.js 可能在 <head> 加载（面板 DOM 尚未解析），故延迟到 DOM 就绪再挂 #mgHDock */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupMgHDock);
  } else {
    setupMgHDock();
  }

  expose();
})();
