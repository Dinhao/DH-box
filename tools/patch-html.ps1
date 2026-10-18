# DH-BOX：把前端原型 cipherbox-ui.html 接到 C# 加密后端（WebView2 bridge）
# 用法：powershell -ExecutionPolicy Bypass -File .\tools\patch-html.ps1
$ErrorActionPreference = 'Stop'

$path = Join-Path $PSScriptRoot '..\web\cipherbox-ui.html'
$path = [IO.Path]::GetFullPath($path)
if (-not (Test-Path $path)) { throw "找不到 $path" }

$raw  = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
$crlf = $raw.Contains("`r`n")
$text = $raw.Replace("`r`n", "`n")

$patch = @()

# ---------------- R1 桥接注入 ----------------
$patch += @{
  Name = 'R1 注入 C# 桥接层'
  Old = @'
"use strict";
'@
  New = @'
"use strict";

/* ================= DH-BOX C# 后端桥接（WebView2 postMessage） ================= */
const bridge = (() => {
  let seq = 0;
  const pending = new Map();
  const wv = window.chrome && window.chrome.webview ? window.chrome.webview : null;
  function post(cmd, args) {
    return new Promise((resolve, reject) => {
      if (!wv) { reject(new Error("未在 DH-BOX 宿主的 WebView2 中运行")); return; }
      const id = "r" + (++seq);
      pending.set(id, { resolve, reject });
      wv.postMessage(JSON.stringify({ id, cmd, args: args || {} }));
    });
  }
  if (wv) {
    wv.addEventListener("message", (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.id && pending.has(msg.id)) {
        const p = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.ok) p.resolve(msg.data || {}); else p.reject(new Error(msg.error || "操作失败"));
        return;
      }
      if (msg.event) handleHostEvent(msg);
    });
  }
  return { post, host: !!wv };
})();
function handleHostEvent(msg) {
  if (msg.event === "autolock") doAutoLock();
}
'@
}

# ---------------- R2 状态层：localStorage → C# 加密存储 ----------------
$patch += @{
  Name = 'R2 状态层改走加密后端'
  Old = @'
/* ---------- 状态加载（含 v1 → v2 迁移） ---------- */
const LS_KEY = "dhbox-ui-proto-v2";
let state = loadState();

function loadState() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const s = JSON.parse(raw);
      if (s && s.tree && s.settings && s.logs) {
        s.columns = Array.isArray(s.columns) ? s.columns.filter((c) => c in COLUMN_DEFS) : [...DEFAULT_COLUMNS];
        s.clipboard = null;
        if (s.theme !== "dark" && s.theme !== "light") s.theme = "light";
        if (s.passwordSet === undefined) s.passwordSet = !!s.password;
        if (s.locked === undefined) s.locked = false;
        if (s.password === undefined) s.password = "";
        return s;
      }
    }
  } catch {}
  // 旧版数据迁移
  try {
    const old = localStorage.getItem("cipherbox-ui-proto-v1");
    if (old) {
      const s = JSON.parse(old);
      if (s && s.tree && s.settings && s.logs) {
        s.theme = "light";
        s.columns = [...DEFAULT_COLUMNS];
        s.clipboard = null;
        s.passwordSet = !!s.password;
        s.locked = false;
        if (!s.tree.mtime) s.tree.mtime = "2026-09-01 10:00";
        if (!s.tree.ctime) s.tree.ctime = s.tree.mtime;
        walkTree(s.tree, (f) => {
          if (!f.mtime) f.mtime = "2026-09-01 10:00";
          if (!f.ctime) f.ctime = f.mtime;
          if (f.enc === undefined) f.enc = true;
        });
        persist();
        return s;
      }
    }
  } catch {}
  const s = seedData();
  persist();
  return s;
}
function persist() {
  try { localStorage.setItem(LS_KEY, JSON.stringify(state)); } catch {}
}
'@
  New = @'
/* ---------- 状态（由 C# 后端加密保存在保险库内，前端只持有内存副本） ---------- */
let state = emptyState();
let sessionUnlockStart = Date.now();

function emptyState() {
  const d = now();
  const stamp = `${fmtDate(d)} ${fmtClock(d)}`;
  return {
    passwordSet: false, locked: false, theme: "light",
    columns: [...DEFAULT_COLUMNS], clipboard: null, cwd: [],
    tree: { name: "", type: "dir", children: [], ctime: stamp, mtime: stamp },
    settings: { lockMode: "duration", durationMinutes: 20, unlockUntil: null },
    logs: [],
  };
}

// 每次状态变化都交给 C# 后端加密写入保险库（替代原型里的 localStorage.setItem）
function persist() {
  bridge.post("saveState", { state: JSON.parse(JSON.stringify(state)) }).catch(() => {});
}

function cwdPath() { return state.cwd.map((s) => s.name).join("/"); }

// 解锁成功后：用后端返回的加密状态覆盖内存副本并整体重绘
function applyStateFromHost(s) {
  state = s || emptyState();
  if (state.theme !== "dark" && state.theme !== "light") state.theme = "light";
  state.columns = Array.isArray(state.columns) ? state.columns.filter((c) => c in COLUMN_DEFS) : [...DEFAULT_COLUMNS];
  if (!state.columns.length) state.columns = [...DEFAULT_COLUMNS];
  if (!state.settings) state.settings = { lockMode: "duration", durationMinutes: 20, unlockUntil: null };
  if (!Array.isArray(state.logs)) state.logs = [];
  if (!Array.isArray(state.cwd)) state.cwd = [];
  state.clipboard = null;
  state.passwordSet = true;
  state.locked = false;
  sessionUnlockStart = Date.now();
  applyTheme(state.theme);
  renderAll();
  renderLogs();
  renderLockUI();
}

/* ---------- 后端数据同步 ---------- */
function insertFilesInto(cwdArr, entries) {
  const dir = dirAt(cwdArr);
  if (!dir) return 0;
  let n = 0;
  for (const f of entries) {
    dir.children.push({ name: f.name, type: "file", ext: f.ext, size: f.size, ctime: f.ctime, mtime: f.mtime, enc: true });
    n++;
  }
  return n;
}

async function doImportFiles() {
  let r;
  try { r = await bridge.post("importFiles", { cwd: cwdPath() }); }
  catch (e) { toast("导入失败：" + e.message, "err"); return; }
  if (!r.entries || !r.entries.length) return;
  insertFilesInto(state.cwd.map((s) => s.name), r.entries);
  addLog("info", `导入文件：${r.entries.map((x) => x.name).join("、")}（${dirLabel()}）`);
  persist();
  renderAll();
  toast(`已导入 ${r.entries.length} 个文件（AES-256 加密入库）`, "ok");
}

async function doImportFolder() {
  let r;
  try { r = await bridge.post("importFolder", { cwd: cwdPath() }); }
  catch (e) { toast("导入失败：" + e.message, "err"); return; }
  if (!r.folder) return;
  const dir = dirAt(state.cwd.map((s) => s.name));
  if (!dir) return;
  const d = now();
  const stamp = `${fmtDate(d)} ${fmtClock(d)}`;
  const root = { name: r.folder, type: "dir", children: [], ctime: r.ctime || stamp, mtime: r.mtime || stamp };
  dir.children.push(root);
  const place = (node, parts, en) => {
    if (!parts.length) {
      node.children.push({ name: en.name, type: "file", ext: en.ext, size: en.size, ctime: en.ctime, mtime: en.mtime, enc: true });
      return;
    }
    const seg = parts.shift();
    let next = node.children.find((c) => c.type === "dir" && c.name === seg);
    if (!next) { next = { name: seg, type: "dir", children: [], ctime: stamp, mtime: stamp }; node.children.push(next); }
    place(next, parts, en);
  };
  for (const en of (r.entries || [])) {
    const parts = en.relPath.split("/");
    const leaf = parts[parts.length - 1];
    place(root, parts.slice(0, -1), { name: leaf, ext: en.ext, size: en.size, ctime: en.ctime, mtime: en.mtime });
  }
  addLog("info", `导入文件夹：${r.folder}（${r.count || 0} 个文件）（${dirLabel()}）`);
  persist();
  renderAll();
  toast(`已导入文件夹「${r.folder}」（${r.count || 0} 个文件）`, "ok");
}

// “解密”菜单：把明文副本导出到本机（保险库内文件始终为 AES-256 密文）
async function doDecrypt(item) {
  try {
    if (item.type === "dir") {
      const r = await bridge.post("decryptFolder", { cwd: cwdPath(), name: item.name });
      addLog("info", `解密导出：${item.name}（${r.count} 个文件）（${dirLabel()}）`);
      toast(`「${item.name}」已解密导出（${r.count} 个文件）`, "ok");
    } else {
      await bridge.post("decryptFile", { cwd: cwdPath(), name: item.name });
      addLog("info", `解密导出：${item.name}（${dirLabel()}）`);
      toast(`「${item.name}」已解密导出`, "ok");
    }
  } catch (e) {
    if (e && e.message === "已取消") return;
    toast("解密导出失败：" + e.message, "err");
  }
}

// 自动锁定：由前端计时（与原型一致），到点先保存状态再让后端清除密钥
async function doAutoLock() {
  if (state.locked || !state.passwordSet) return;
  const s = state.settings || {};
  addLog("info", s.lockMode === "until" ? "自动锁定：到达定点临时解锁截止时刻" : `自动锁定：空闲超过 ${s.durationMinutes || 20} 分钟`);
  try { await bridge.post("lock", {}); } catch {}
  state.locked = true;
  showLockOverlay();
  toast("保险库已自动锁定", "ok");
}
'@
}

# ---------------- R3 打开文件 → 后端解密并用系统程序打开 ----------------
$patch += @{
  Name = 'R3 打开文件接后端'
  Old = @'
  } else {
    toast(`已打开文件「${f.name}」`, "ok");
    addLog("info", `打开文件：${f.name}（${dirLabel()}）`);
  }
}
'@
  New = @'
  } else {
    toast(`已打开文件「${f.name}」`, "ok");
    addLog("info", `打开文件：${f.name}（${dirLabel()}）`);
    bridge.post("openFile", { cwd: cwdPath(), name: f.name })
      .catch((e) => { toast("打开失败：" + e.message, "err"); addLog("error", `打开文件失败：${f.name}（${e.message}）`); });
  }
}
'@
}

# ---------------- R4 空白右键菜单补充导入入口 ----------------
$patch += @{
  Name = 'R4 空白菜单加导入入口'
  Old = @'
    entries.push({ ico: "📁", label: "新建文件夹", act: "newFolder" });
    entries.push({ ico: "📥", label: "粘贴", act: "paste", disabled: clipboardEmpty() });
'@
  New = @'
    entries.push({ ico: "📁", label: "新建文件夹", act: "newFolder" });
    entries.push({ ico: "📤", label: "导入文件…", act: "importFiles" });
    entries.push({ ico: "📂", label: "导入文件夹…", act: "importFolder" });
    entries.push({ ico: "📥", label: "粘贴", act: "paste", disabled: clipboardEmpty() });
'@
}

# ---------------- R5 菜单动作分发 ----------------
$patch += @{
  Name = 'R5a encrypt 动作改解密导出'
  Old = @'
    case "encrypt": toggleEncrypt(item); break;
'@
  New = @'
    case "encrypt": doDecrypt(item); break;
'@
}
$patch += @{
  Name = 'R5b 增加导入动作'
  Old = @'
    case "newFolder": $("btnNewFolder").click(); break;
'@
  New = @'
    case "newFolder": $("btnNewFolder").click(); break;
    case "importFiles": doImportFiles(); break;
    case "importFolder": doImportFolder(); break;
'@
}

# ---------------- R6 粘贴（移动/复制）真实同步容器 ----------------
$patch += @{
  Name = 'R6 doPaste 接后端'
  Old = @'
function doPaste(targetDir) {
  if (clipboardEmpty()) { toast("剪贴板为空", "err"); return; }
  const c = state.clipboard;
  const srcDir = dirAt(c.fromDir);
  if (!srcDir) { clearClipboard(); toast("原位置已不存在", "err"); return; }
  const curDir = dirAt(state.cwd.map((s) => s.name));
  const dest = targetDir || curDir;
  if (!dest) { toast("目标目录不存在", "err"); return; }
  // 目标路径（相对根）：当前路径 + （粘贴到子文件夹时追加其名）
  const destPath = state.cwd.map((s) => s.name).concat(dest === curDir ? [] : [dest.name]);  if (c.mode === "cut") {
    // 剪切：目录防套娃（不能移入自身或自身子目录）
    if (c.item.type === "dir" && dirContains(c.item, destPath)) {
      toast("不能把文件夹移动到它自身或其子文件夹中", "err");
      return;
    }
    const idx = srcDir.children.indexOf(c.item);
    if (idx < 0) { clearClipboard(); toast("项目已被移除", "err"); return; }
    if (srcDir === dest) { clearClipboard(); return; } // 原位置粘贴 = 无操作
    c.item.name = uniqueName(c.item.name, dest.children, c.item.type === "dir");
    srcDir.children.splice(idx, 1);
    dest.children.push(c.item);
    addLog("info", `移动：${c.item.name} → ${destPath.length ? pathJoin(destPath) : "根目录"}`);
    clearClipboard();
    toast(`已移动「${c.item.name}」`, "ok");
  } else {
    const clone = JSON.parse(JSON.stringify(c.item));
    clone.name = uniqueName(clone.name, dest.children, clone.type === "dir");
    dest.children.push(clone);
    addLog("info", `复制：${clone.name} → ${destPath.length ? pathJoin(destPath) : "根目录"}`);
    toast(`已粘贴「${clone.name}」`, "ok");
  }
  persist();
  renderAll();
}
'@
  New = @'
async function doPaste(targetDir) {
  if (clipboardEmpty()) { toast("剪贴板为空", "err"); return; }
  const c = state.clipboard;
  const srcDir = dirAt(c.fromDir);
  if (!srcDir) { clearClipboard(); toast("原位置已不存在", "err"); return; }
  const curDir = dirAt(state.cwd.map((s) => s.name));
  const dest = targetDir || curDir;
  if (!dest) { toast("目标目录不存在", "err"); return; }
  // 目标路径（相对根）：当前路径 + （粘贴到子文件夹时追加其名）
  const destPath = state.cwd.map((s) => s.name).concat(dest === curDir ? [] : [dest.name]);
  const toPath = destPath.join("/");
  if (c.mode === "cut") {
    // 剪切：目录防套娃（不能移入自身或自身子目录）
    if (c.item.type === "dir" && dirContains(c.item, destPath)) {
      toast("不能把文件夹移动到它自身或其子文件夹中", "err");
      return;
    }
    const idx = srcDir.children.indexOf(c.item);
    if (idx < 0) { clearClipboard(); toast("项目已被移除", "err"); return; }
    if (srcDir === dest) { clearClipboard(); return; } // 原位置粘贴 = 无操作
    let finalName = c.item.name;
    try {
      const r = await bridge.post("move", { fromCwd: (c.fromDir || []).join("/"), name: c.item.name, toCwd: toPath });
      if (r && r.name) finalName = r.name;
    } catch (e) { toast("移动失败：" + e.message, "err"); return; }
    srcDir.children.splice(idx, 1);
    c.item.name = finalName;
    dest.children.push(c.item);
    addLog("info", `移动：${finalName} → ${destPath.length ? pathJoin(destPath) : "根目录"}`);
    clearClipboard();
    toast(`已移动「${finalName}」`, "ok");
  } else {
    let finalName = null;
    try {
      const r = await bridge.post("copy", { fromCwd: (c.fromDir || []).join("/"), name: c.item.name, toCwd: toPath });
      if (r && r.name) finalName = r.name;
    } catch (e) { toast("粘贴失败：" + e.message, "err"); return; }
    const clone = JSON.parse(JSON.stringify(c.item));
    clone.name = finalName || uniqueName(clone.name, dest.children, clone.type === "dir");
    dest.children.push(clone);
    addLog("info", `复制：${clone.name} → ${destPath.length ? pathJoin(destPath) : "根目录"}`);
    toast(`已粘贴「${clone.name}」`, "ok");
  }
  persist();
  renderAll();
}
'@
}

# ---------------- R7 重命名真实同步 ----------------
$patch += @{
  Name = 'R7 重命名接后端'
  Old = @'
$("btnRenameConfirm").onclick = () => {
  const item = ctxTarget && ctxTarget.kind === "item" ? ctxTarget.item : null;
  if (!item) return;
  const name = $("renameInput").value.trim();
  const err = $("renameErr");
  err.textContent = "";
  if (!name) { err.textContent = "名称不能为空"; return; }
  if (INVALID_CHARS.test(name)) { err.textContent = "名称不能包含 \\ / : * ? \" < > | 字符"; return; }
  if (name === item.name) { $("renameModal").classList.remove("visible"); return; }
  const siblings = listItems().filter((c) => c !== item);
  if (siblings.some((c) => c.name === name && c.type === item.type)) { err.textContent = "已存在同名项目"; return; }
  const oldName = item.name;
  item.name = name;
  addLog("info", `重命名：${oldName} → ${name}（${dirLabel()}）`);
  persist();
  $("renameModal").classList.remove("visible");
  selectedName = name;
  renderAll();
  toast(`已重命名为「${name}」`, "ok");
};
'@
  New = @'
$("btnRenameConfirm").onclick = async () => {
  const item = ctxTarget && ctxTarget.kind === "item" ? ctxTarget.item : null;
  if (!item) return;
  const name = $("renameInput").value.trim();
  const err = $("renameErr");
  err.textContent = "";
  if (!name) { err.textContent = "名称不能为空"; return; }
  if (INVALID_CHARS.test(name)) { err.textContent = "名称不能包含 \\ / : * ? \" < > | 字符"; return; }
  if (name === item.name) { $("renameModal").classList.remove("visible"); return; }
  const siblings = listItems().filter((c) => c !== item);
  if (siblings.some((c) => c.name === name && c.type === item.type)) { err.textContent = "已存在同名项目"; return; }
  const oldName = item.name;
  try { await bridge.post("rename", { cwd: cwdPath(), name: oldName, newName: name }); }
  catch (e) { err.textContent = "重命名失败：" + e.message; return; }
  item.name = name;
  addLog("info", `重命名：${oldName} → ${name}（${dirLabel()}）`);
  persist();
  $("renameModal").classList.remove("visible");
  selectedName = name;
  renderAll();
  toast(`已重命名为「${name}」`, "ok");
};
'@
}

# ---------------- R8 移除原型“切换加密标记” ----------------
$patch += @{
  Name = 'R8 移除 toggleEncrypt'
  Old = @'
function toggleEncrypt(item) {
  const setEnc = (node) => { node.enc = !item.enc; if (node.type === "dir") node.children.forEach(setEnc); };
  setEnc(item);
  addLog(item.enc ? "ok" : "warn", `${item.enc ? "加密" : "解密"}：${item.name}（${dirLabel()}）`);
  persist();
  renderAll();
  toast(`「${item.name}」已${item.enc ? "加密" : "解密"}`, "ok");
}
'@
  New = @'
// 原型里的 encrypt/decrypt 切换已由真实“解密导出”（doDecrypt）取代：
// 保险库内所有文件始终以 AES-256 加密存储，不存在“未加密条目”。
'@
}

# ---------------- R9 删除真实同步 ----------------
$patch += @{
  Name = 'R9 删除接后端'
  Old = @'
$("btnDeleteConfirm").onclick = () => {
  const item = ctxTarget && ctxTarget.kind === "item" ? ctxTarget.item : null;
  if (!item) return;
  const dir = dirAt(state.cwd.map((s) => s.name));
  const idx = dir.children.indexOf(item);
  if (idx >= 0) dir.children.splice(idx, 1);
  addLog("warn", `删除：${item.name}（${dirLabel()}）`);
  if (state.clipboard && state.clipboard.item === item) clearClipboard();
  persist();
  $("deleteModal").classList.remove("visible");
  if (selectedName === item.name) selectedName = null;
  renderAll();
  toast(`已删除「${item.name}」`, "ok");
};
'@
  New = @'
$("btnDeleteConfirm").onclick = async () => {
  const item = ctxTarget && ctxTarget.kind === "item" ? ctxTarget.item : null;
  if (!item) return;
  try { await bridge.post("delete", { cwd: cwdPath(), name: item.name }); }
  catch (e) { toast("删除失败：" + e.message, "err"); return; }
  const dir = dirAt(state.cwd.map((s) => s.name));
  const idx = dir.children.indexOf(item);
  if (idx >= 0) dir.children.splice(idx, 1);
  addLog("warn", `删除：${item.name}（${dirLabel()}）`);
  if (state.clipboard && state.clipboard.item === item) clearClipboard();
  persist();
  $("deleteModal").classList.remove("visible");
  if (selectedName === item.name) selectedName = null;
  renderAll();
  toast(`已删除「${item.name}」`, "ok");
};
'@
}

# ---------------- R10 属性文案：GCM → CBC+HMAC ----------------
$patch += @{
  Name = 'R10 属性加密算法文案'
  Old = @'
  rows.push(["加密状态", item.enc ? "🔒 已加密（AES-256-GCM）" : "未加密"]);
'@
  New = @'
  rows.push(["加密状态", item.enc ? "🔒 已加密（AES-256）" : "未加密"]);
'@
}

# ---------------- R11a 修改密码走后端 ----------------
$patch += @{
  Name = 'R11a 修改密码接后端'
  Old = @'
$("btnChangePw").onclick = () => {
  const old = $("pwOld").value, nw = $("pwNew").value, cf = $("pwConfirm").value;
  const err = $("pwErr");
  err.textContent = "";
  if (b64Decode(state.password) !== old) { err.textContent = "旧密码不正确"; return; }
  if (nw.length < 6) { err.textContent = "新密码至少 6 位"; return; }
  if (nw !== cf) { err.textContent = "两次输入的新密码不一致"; return; }
  if (nw === old) { err.textContent = "新密码不能与旧密码相同"; return; }
  state.password = b64Encode(nw);
  state.passwordSet = true;
  persist();
  addLog("ok", "主密码修改成功");
  $("pwOld").value = $("pwNew").value = $("pwConfirm").value = "";
  refreshStrength();
  toast("密码修改成功", "ok");
};
'@
  New = @'
$("btnChangePw").onclick = async () => {
  const old = $("pwOld").value, nw = $("pwNew").value, cf = $("pwConfirm").value;
  const err = $("pwErr");
  err.textContent = "";
  if (!old) { err.textContent = "旧密码不正确"; return; }
  if (nw.length < 6) { err.textContent = "新密码至少 6 位"; return; }
  if (nw !== cf) { err.textContent = "两次输入的新密码不一致"; return; }
  if (nw === old) { err.textContent = "新密码不能与旧密码相同"; return; }
  try { await bridge.post("changePassword", { oldPassword: old, newPassword: nw }); }
  catch (e) { err.textContent = e.message; return; }
  addLog("ok", "主密码修改成功");
  $("pwOld").value = $("pwNew").value = $("pwConfirm").value = "";
  refreshStrength();
  toast("密码修改成功", "ok");
};
'@
}

# ---------------- R11b 锁定按钮走后端 ----------------
$patch += @{
  Name = 'R11b 锁定按钮接后端'
  Old = @'
$("btnLock").onclick = () => {
  if (!state.passwordSet || !state.password) { toast("尚未设置主密码，无法锁定", "err"); return; }
  state.locked = true;
  persist();
  addLog("info", "保险库已锁定（手动锁定）");
  showLockOverlay();
};
'@
  New = @'
$("btnLock").onclick = async () => {
  if (!state.passwordSet) { toast("尚未设置主密码，无法锁定", "err"); return; }
  addLog("info", "保险库已锁定（手动锁定）");
  try { await bridge.post("saveState", { state: JSON.parse(JSON.stringify(state)) }); } catch {}
  try { await bridge.post("lock", {}); } catch {}
  state.locked = true;
  showLockOverlay();
  toast("保险库已锁定", "ok");
};
'@
}

# ---------------- R11c 解锁校验走后端 ----------------
$patch += @{
  Name = 'R11c 解锁接后端'
  Old = @'
$("btnUnlock").onclick = () => {
  const pass = $("unlockPass").value;
  const err = $("unlockErr");
  err.textContent = "";
  if (!pass) { err.textContent = "请输入主密码"; return; }
  if (b64Decode(state.password) !== pass) { err.textContent = "密码不正确"; return; }
  state.locked = false;
  persist();
  addLog("ok", "保险库解锁成功（密码验证通过）");
  hideLockOverlay();
  toast("已解锁", "ok");
};
'@
  New = @'
$("btnUnlock").onclick = async () => {
  const pass = $("unlockPass").value;
  const err = $("unlockErr");
  err.textContent = "";
  if (!pass) { err.textContent = "请输入主密码"; return; }
  let data;
  try { data = await bridge.post("unlock", { password: pass }); }
  catch (e) { err.textContent = e.message; return; }
  applyStateFromHost(data.state);
  addLog("ok", "保险库解锁成功（密码验证通过）");
  persist();
  hideLockOverlay();
  toast("已解锁", "ok");
};
'@
}

# ---------------- R11d 首次设置密码走后端 ----------------
$patch += @{
  Name = 'R11d 设置主密码接后端'
  Old = @'
$("btnSetupConfirm").onclick = () => {
  const pass = $("setupPass").value, cf = $("setupPassConfirm").value;
  const err = $("setupErr");
  err.textContent = "";
  if (pass.length < 6) { err.textContent = "主密码至少 6 位"; return; }
  if (pass !== cf) { err.textContent = "两次输入的密码不一致"; return; }
  state.password = b64Encode(pass);
  state.passwordSet = true;
  state.locked = false;
  persist();
  addLog("ok", "主密码设置完成");
  $("setupModal").classList.remove("visible");
  toast("主密码设置成功", "ok");
};
'@
  New = @'
$("btnSetupConfirm").onclick = async () => {
  const pass = $("setupPass").value, cf = $("setupPassConfirm").value;
  const err = $("setupErr");
  err.textContent = "";
  if (pass.length < 6) { err.textContent = "主密码至少 6 位"; return; }
  if (pass !== cf) { err.textContent = "两次输入的密码不一致"; return; }
  try { await bridge.post("setup", { password: pass }); }
  catch (e) { err.textContent = e.message; return; }
  state.passwordSet = true;
  state.locked = false;
  sessionUnlockStart = Date.now();
  addLog("ok", "主密码设置完成（保险库已按 AES-256 加密创建）");
  persist();
  $("setupModal").classList.remove("visible");
  toast("主密码设置成功", "ok");
};
'@
}

# ---------------- R12 自动锁定判定 ----------------
$patch += @{
  Name = 'R12 自动锁定前端判定'
  Old = @'
setInterval(() => { if (state.settings.lockMode === "until") updateDeadlineNote(); }, 1000);
'@
  New = @'
setInterval(() => {
  if (state.settings.lockMode === "until") updateDeadlineNote();
  if (state.locked || !state.passwordSet) return;
  const s = state.settings;
  if (s.lockMode === "duration" && s.durationMinutes) {
    if (Date.now() - sessionUnlockStart >= s.durationMinutes * 60000) doAutoLock();
  } else if (s.lockMode === "until" && s.unlockUntil) {
    if (Date.now() >= s.unlockUntil) doAutoLock();
  }
}, 1000);
'@
}

# ---------------- R13 启动流程：接后端 ----------------
$patch += @{
  Name = 'R13 启动流程接后端'
  Old = @'
/* ---------- 启动 ---------- */
// 设计稿截图模式：通过 URL 参数精确控制初始界面（不影响默认使用）
const shotParams = new URLSearchParams(location.search);
const shotMode = shotParams.get("mode");      // main | setup | lock | settings
const shotTab = shotParams.get("tab");        // password | logs | autolock
const shotTheme = shotParams.get("theme");    // light | dark

applyTheme(shotTheme === "light" || shotTheme === "dark" ? shotTheme : state.theme);
renderAll();
renderLogs();
renderLockUI();

if (shotMode === "main") {
  showView("main");
  updateStatusPill();
} else if (shotMode === "setup") {
  showView("main");
  $("setupModal").classList.add("visible");
  $("setupPass").focus();
} else if (shotMode === "lock") {
  showView("main");
  showLockOverlay();
} else if (shotMode === "settings") {
  const tab = shotTab && ["password", "logs", "autolock"].includes(shotTab) ? shotTab : "password";
  showView("settings");
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.tab === tab));
  document.querySelectorAll(".settings-tab").forEach((t) => t.classList.toggle("visible", t.id === "tab-" + tab));
  if (tab === "logs") renderLogs();
  if (tab === "autolock") renderLockUI();
  updateStatusPill();
} else {
  showView("main");
  if (!state.passwordSet || !state.password) {
    $("setupModal").classList.add("visible");
    setTimeout(() => $("setupPass").focus(), 30);
  } else if (state.locked) {
    showLockOverlay();
  } else {
    updateStatusPill();
  }
}
'@
  New = @'
/* ---------- 启动 ---------- */
// 设计稿截图模式：通过 URL 参数精确控制初始界面（仅用于界面核对）
const shotParams = new URLSearchParams(location.search);
const shotMode = shotParams.get("mode");      // main | setup | lock | settings
const shotTab = shotParams.get("tab");        // password | logs | autolock
const shotTheme = shotParams.get("theme");    // light | dark

function renderShell() {
  applyTheme(shotTheme === "light" || shotTheme === "dark" ? shotTheme : state.theme);
  renderAll();
  renderLogs();
  renderLockUI();
}

async function bootApp() {
  if (shotMode) {
    // 界面核对模式（不接后端）：用内存空状态渲染指定界面
    state = emptyState();
    state.passwordSet = shotMode !== "setup";
    state.locked = shotMode === "lock";
    renderShell();
    showView("main");
    if (shotMode === "setup") {
      $("setupModal").classList.add("visible");
      $("setupPass").focus();
    } else if (shotMode === "lock") {
      showLockOverlay();
    } else if (shotMode === "settings") {
      const tab = shotTab && ["password", "logs", "autolock"].includes(shotTab) ? shotTab : "password";
      showView("settings");
      document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.tab === tab));
      document.querySelectorAll(".settings-tab").forEach((t) => t.classList.toggle("visible", t.id === "tab-" + tab));
      if (tab === "logs") renderLogs();
      if (tab === "autolock") renderLockUI();
      updateStatusPill();
    } else {
      updateStatusPill();
    }
    return;
  }

  let boot;
  try { boot = await bridge.post("boot", {}); }
  catch (e) {
    document.body.innerHTML = `<div style="padding:48px;font:14px/1.8 'Microsoft YaHei UI',sans-serif;color:#57607a">` +
      `⚠️ 未能连接 DH-BOX 加密后端<br><br>请通过 DH-BOX.exe 启动本界面（C# 后端负责全部加密读写）。` +
      `<br><span style="color:#98a2b8">${esc(e.message)}</span></div>`;
    return;
  }

  if (!boot.hasVault) {
    // 首次使用：设置主密码
    state = emptyState();
    state.passwordSet = false;
    renderShell();
    showView("main");
    updateStatusPill();
    $("setupModal").classList.add("visible");
    setTimeout(() => $("setupPass").focus(), 30);
    return;
  }

  // 已有保险库：以锁定状态启动，等待在覆盖层输入主密码
  state = emptyState();
  state.passwordSet = true;
  state.locked = true;
  renderShell();
  showView("main");
  showLockOverlay();
}

bootApp();
'@
}

function Norm([string]$s) { return $s.Replace("`r`n", "`n") }

# ---------------- 执行 ----------------
$fail = 0
foreach ($p in $patch) {
  $old = Norm $p.Old; $new = Norm $p.New
  $cnt = ([regex]::Matches($text, [regex]::Escape($old))).Count
  if ($cnt -ne 1) {
    Write-Host ("❌ {0} —— 命中 {1} 次（应为 1）" -f $p.Name, $cnt)
    $fail++
    continue
  }
  $text = $text.Replace($old, $new)
  Write-Host ("✅ " + $p.Name)
}

if ($fail -gt 0) {
  Write-Host ""
  Write-Host "有补丁未命中，已放弃写回（文件未改动）。"
  exit 1
}

if ($crlf) { $text = $text.Replace("`n", "`r`n") }
[IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
Write-Host ""
Write-Host ("补丁全部应用并写回：{0}（{1} 字节）" -f $path, $text.Length)
