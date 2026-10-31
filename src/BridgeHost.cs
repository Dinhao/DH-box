using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;

namespace SecretVault
{
    /// <summary>
    /// JS ↔ C# 桥接（WebView2 WebMessage）：
    ///   前端：chrome.webview.postMessage(JSON.stringify({id, cmd, args}))
    ///   后端：本类执行真实操作后 PostWebMessageAsJson({id, ok, data | error})
    /// 所有数据读写都经过 <see cref="VaultFile"/>（AES-256-CBC + HMAC-SHA256 加密容器）；
    /// 界面状态（目录树/设置/日志）整体作为 JSON 加密保存在容器内的 <c>.dhbox-state.json</c> 条目中。
    ///
    /// 安全设计（本层为界面适配层，不含任何加密/密钥派生逻辑）：
    ///   · 命令白名单：仅分发固定命令集，未知命令一律拒绝；
    ///   · 来源白名单：只接受本地界面站点 https://dhbox.local 的消息；
    ///   · 权限分级：数据类命令必须先解锁（RequireUnlocked），锁定时一律拒绝；
    ///   · 参数白名单：条目路径逐段校验（禁 ..、绝对路径、非法字符、系统保留条目）；
    ///   · 敏感数据：密码/密钥不写日志、不回传前端；明文临时文件用后即删。
    /// </summary>
    internal class BridgeHost
    {
        /// <summary>界面状态在容器内的条目路径（加密保存，前端不可见，禁止通过命令操作）。</summary>
        private const string StateEntry = ".dhbox-state.json";

        private const int PasswordMaxLength = 256;                 // 密码长度上限
        private const long StateMaxBytes = 2 * 1024 * 1024;        // 界面状态大小上限（2 MB）
        private const int PathMaxLength = 1024;                    // 条目路径长度上限
        private const int PathMaxSegments = 32;                    // 条目路径层数上限

        private readonly HostForm form;
        private readonly AppConfig cfg;
        private readonly string vaultPath;
        private readonly JavaScriptSerializer json = new();

        /// <summary>已打开的临时解密文件：容器条目 →（本地文件, 解密时刻），退出/锁定时回写修改。</summary>
        private readonly Dictionary<string, (string Local, DateTime At)> openedFiles = new();

        /// <summary>系统图标缓存（扩展名 / __dir__ → data:image/png;base64）。</summary>
        private readonly Dictionary<string, string> iconCache = new();

        private MasterKeys? master;

        public BridgeHost(HostForm form)
        {
            this.form = form;
            cfg = AppConfig.Load();
            vaultPath = Program.ResolveVaultPath();
        }

        /* ================= 消息入口 ================= */

        public void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            // 来源白名单：只有本地界面站点（web 目录映射）可以调用桥接
            if (!IsTrustedSource(e.Source))
            {
                Logger.Write("安全", "已拒绝非本地界面的桥接消息（来源不合法）");
                return;
            }

            string raw;
            try { raw = e.TryGetWebMessageAsString(); }
            catch { return; }
            if (raw.Length > 16 * 1024 * 1024) return;   // 单条消息体上限

            Dictionary<string, object>? msg;
            try { msg = json.DeserializeObject(raw) as Dictionary<string, object>; }
            catch { return; }
            if (msg == null) return;

            string id = S(msg, "id");
            string cmd = S(msg, "cmd");
            var args = msg.TryGetValue("args", out var a) && a is Dictionary<string, object> d
                ? d
                : new Dictionary<string, object>();

            _ = HandleAsync(id, cmd, args);
        }

        private async Task HandleAsync(string id, string cmd, Dictionary<string, object> args)
        {
            try
            {
                object? data = await DispatchAsync(cmd, args);
                Reply(id, true, data, null);
            }
            catch (Exception ex)
            {
                // 注意：不回显堆栈、不记录参数内容（避免敏感数据进入日志与前端）
                Logger.Write("桥接", $"命令 {Clean(cmd, 32)} 被拒绝/失败：{Clean(ex.Message, 200)}");
                Reply(id, false, null, ex.Message);
            }
        }

        private void Reply(string id, bool ok, object? data, string? error)
        {
            var payload = new Dictionary<string, object?> { ["id"] = id, ["ok"] = ok };
            if (data != null) payload["data"] = data;
            if (!string.IsNullOrEmpty(error)) payload["error"] = error;
            PostJson(json.Serialize(payload));
        }

        /// <summary>向网页发送事件（无请求 id）：{event, data}。</summary>
        public void PostEvent(string evt, object? data)
        {
            PostJson(json.Serialize(new Dictionary<string, object?> { ["event"] = evt, ["data"] = data }));
        }

        private void PostJson(string jsonText)
        {
            if (form.IsDisposed) return;
            bool debug = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DHBOX_SHOT"));
            try
            {
                form.BeginInvoke((Action)(() =>
                {
                    try
                    {
                        form.View.CoreWebView2?.PostWebMessageAsJson(jsonText);
                        if (debug) Logger.Write("桥接", $"回复已发送（{jsonText.Length} 字节）");
                    }
                    catch (Exception ex)
                    {
                        if (debug) Logger.Write("桥接", "回复发送失败：" + ex.Message);
                    }
                }));
            }
            catch { }
        }

        /* ================= 命令分发（白名单） ================= */

        private async Task<object?> DispatchAsync(string cmd, Dictionary<string, object> args)
        {
            switch (cmd)
            {
                case "boot":
                    Logger.Write("桥接", "前端网页已连接（boot）");
                    return new
                    {
                        hasVault = File.Exists(vaultPath),
                        locked = master == null,
                        logPath = Logger.LogFilePath,   // 供界面“查看日志”页显示真实路径（与程序同目录）
                    };

                case "setup":
                {
                    if (File.Exists(vaultPath)) throw new Exception("保险库已存在。");
                    string pwd = S(args, "password");
                    if (pwd.Length < 6) throw new Exception("主密码至少 6 位");
                    if (pwd.Length > PasswordMaxLength) throw new Exception($"密码过长（上限 {PasswordMaxLength} 字符）");
                    VaultFile.Create(vaultPath, pwd);
                    master = VaultFile.TryUnlock(vaultPath, pwd, out var e1) ?? throw new Exception(e1);
                    cfg.VaultPath = vaultPath;
                    cfg.Save();
                    Logger.Write("保险库", "已创建保险库：" + vaultPath);
                    return new { ok = true };
                }

                case "unlock":
                {
                    if (master != null) return new { state = LoadStateObject() };
                    if (LockoutPolicy.IsLocked(cfg))
                        throw new Exception($"密码错误次数过多，已临时锁定，请在 {LockoutPolicy.RemainingText(cfg)} 后重试");
                    string pwd = S(args, "password");
                    if (pwd.Length == 0) throw new Exception("请输入主密码");
                    if (pwd.Length > PasswordMaxLength) throw new Exception($"密码过长（上限 {PasswordMaxLength} 字符）");
                    var mk = VaultFile.TryUnlock(vaultPath, pwd, out var err);
                    if (mk == null)
                    {
                        LockoutPolicy.OnFailure(cfg);
                        Logger.Write("保险库", "解锁失败（密码错误）");
                        if (LockoutPolicy.IsLocked(cfg))
                            throw new Exception($"连续错误 5 次，已临时锁定，请在 {LockoutPolicy.RemainingText(cfg)} 后重试");
                        throw new Exception($"密码不正确（连续错误 {cfg.PwdFailCount}/5 次后将临时锁定）");
                    }
                    LockoutPolicy.OnSuccess(cfg);
                    master = mk;
                    Logger.Write("保险库", "解锁成功");
                    return new { state = LoadStateObject() };
                }

                case "lock":
                {
                    // 顺序：写回改动 → 清理临时明文 → 清除内存密钥（三步均异常安全，确保密钥必然清零）
                    try { FlushOpenedFiles(); } catch { }
                    try { CleanOpenCache(); } catch { }
                    try { CleanClipCache(); } catch { }
                    master?.Wipe();
                    master = null;
                    Logger.Write("保险库", "已锁定（内存密钥已清除，临时解密文件已清理）");
                    return new { ok = true };
                }

                case "saveState":
                {
                    RequireUnlocked();
                    object st = args.TryGetValue("state", out var sv) && sv != null
                        ? sv
                        : new Dictionary<string, object>();
                    string stateJson = json.Serialize(st);
                    if (stateJson.Length > StateMaxBytes) throw new Exception("界面状态数据过大，已拒绝保存");
                    WriteState(stateJson);
                    return new { ok = true };
                }

                case "changePassword":
                {
                    RequireUnlocked();
                    string o = S(args, "oldPassword"), n = S(args, "newPassword");
                    if (n.Length < 6) throw new Exception("新密码至少 6 位");
                    if (n.Length > PasswordMaxLength || o.Length > PasswordMaxLength)
                        throw new Exception($"密码过长（上限 {PasswordMaxLength} 字符）");
                    if (n == o) throw new Exception("新密码不能与旧密码相同");
                    if (!VaultFile.ChangePassword(vaultPath, o, n, out var err))
                        throw new Exception(err.Contains("密码") ? "旧密码不正确" : err);
                    Logger.Write("保险库", "主密码已修改（文件零重加密）");
                    return new { ok = true };
                }

                case "importFiles":
                {
                    RequireUnlocked();
                    string cwd = SafeEntryPath(S(args, "cwd"));
                    using var dlg = new OpenFileDialog
                    {
                        Title = "导入文件到保险库",
                        Multiselect = true,
                        Filter = "所有文件 (*.*)|*.*",
                    };
                    if (dlg.ShowDialog(form) != DialogResult.OK) throw new Exception("已取消");
                    var before = SnapshotEntries();
                    VaultFile.ImportFiles(vaultPath, master!, dlg.FileNames, cwd);
                    var added = NewEntries(before)
                        .Where(x => x.IsFile && ParentOf(x.Name) == cwd)
                        .Select(FileInfoObj)
                        .ToList();
                    Logger.Write("文件", $"导入 {added.Count} 个文件（{(cwd.Length == 0 ? "根目录" : cwd)}）");
                    return new { entries = added, count = added.Count };
                }

                case "importFolder":
                {
                    RequireUnlocked();
                    string cwd = SafeEntryPath(S(args, "cwd"));
                    using var dlg = new FolderBrowserDialog
                    {
                        Description = "选择要导入保险库的文件夹（原文件夹保持不动）",
                        ShowNewFolderButton = false,
                    };
                    if (dlg.ShowDialog(form) != DialogResult.OK) throw new Exception("已取消");
                    var before = SnapshotEntries();
                    VaultFile.ImportDirectory(vaultPath, master!, dlg.SelectedPath, cwd);
                    var addedAll = NewEntries(before);
                    string? rootFull = addedAll
                        .Where(x => !x.IsFile && ParentOf(x.Name) == cwd)
                        .OrderBy(x => x.Name.Length)
                        .Select(x => x.Name)
                        .FirstOrDefault();
                    if (rootFull == null) throw new Exception("导入失败：未产生任何条目");
                    string prefix = rootFull + "/";
                    var files = addedAll
                        .Where(x => x.IsFile && x.Name.StartsWith(prefix, StringComparison.Ordinal))
                        .Select(x => new
                        {
                            relPath = x.Name.Substring(prefix.Length),
                            isDir = false,
                            ext = ExtOf(x.Leaf),
                            size = x.PlainLength,
                            ctime = Fmt(x.Created),
                            mtime = Fmt(x.Modified),
                        })
                        .ToList();
                    string rootLeaf = rootFull.Substring(rootFull.LastIndexOf('/') + 1);
                    string now = Fmt(DateTime.Now);
                    Logger.Write("文件", $"导入文件夹：{rootLeaf}（{files.Count} 个文件）");
                    return new
                    {
                        folder = rootLeaf,
                        ctime = now,
                        mtime = now,
                        entries = files,
                        count = files.Count,
                    };
                }

                case "rename":
                {
                    RequireUnlocked();
                    string entry = SafeEntryPath(Join(args, "cwd", "name"), false);
                    string newName = SafeLeaf(S(args, "newName"));
                    if (EntryExists(entry))
                    {
                        VaultFile.RenameEntry(vaultPath, master!, entry, newName);
                        Logger.Write("文件", "重命名：" + entry + " → " + newName);
                    }
                    // 仅存在于界面状态中的节点（例如新建的空文件夹）没有容器条目，无需同步
                    return new { ok = true };
                }

                case "delete":
                {
                    RequireUnlocked();
                    string cwd = SafeEntryPath(S(args, "cwd"));
                    var names = S(args, "names").Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim('\r', ' ')).Where(x => x.Length > 0).ToList();
                    if (names.Count == 0) names.Add(S(args, "name"));
                    var paths = new List<string>();
                    foreach (var n in names)
                    {
                        string p = SafeEntryPath(cwd.Length == 0 ? n : cwd + "/" + n, false);
                        if (EntryExists(p)) paths.Add(p);
                    }
                    if (paths.Count > 0)
                    {
                        VaultFile.DeleteEntries(vaultPath, master!, paths);
                        Logger.Write("文件", $"删除 {paths.Count} 项：" + Clean(string.Join("、", paths), 200));
                    }
                    return new { ok = true, count = paths.Count };
                }

                case "move":
                case "copy":
                {
                    RequireUnlocked();
                    string entry = SafeEntryPath(Join(args, "fromCwd", "name"), false);
                    string to = SafeEntryPath(S(args, "toCwd"));
                    if (!EntryExists(entry))
                    {
                        // 仅存在于界面状态中的节点：无需同步容器数据
                        return new { name = S(args, "name") };
                    }
                    var before = SnapshotEntries();
                    if (cmd == "move") VaultFile.MoveEntries(vaultPath, master!, new[] { entry }, to);
                    else VaultFile.CopyEntries(vaultPath, master!, new[] { entry }, to);
                    var landed = NewEntries(before)
                        .Where(x => ParentOf(x.Name) == to)
                        .OrderBy(x => x.Name.Length)
                        .FirstOrDefault();
                    Logger.Write("文件", (cmd == "move" ? "移动：" : "复制：") + entry +
                        " → " + (to.Length == 0 ? "根目录" : to));
                    return new { name = landed?.Leaf ?? S(args, "name") };
                }

                case "openFile":
                {
                    RequireUnlocked();
                    string entry = SafeEntryPath(Join(args, "cwd", "name"), false);
                    var en = VaultFile.ListEntries(vaultPath).FirstOrDefault(x => x.Name == entry && x.IsFile)
                             ?? throw new Exception("保险库中找不到该文件");
                    string dir = EnsureOpenCache();
                    string local = Path.Combine(dir, ShortHash(entry) + "_" + SafeName(en.Leaf));
                    VaultFile.ExtractFile(vaultPath, master!, entry, local);
                    openedFiles[entry] = (local, DateTime.UtcNow);
                    Process.Start(new ProcessStartInfo(local) { UseShellExecute = true });
                    Logger.Write("文件", "打开：" + entry);
                    return new { ok = true, local };
                }

                case "decryptFile":
                {
                    RequireUnlocked();
                    string entry = SafeEntryPath(Join(args, "cwd", "name"), false);
                    string leaf = entry.Substring(entry.LastIndexOf('/') + 1);
                    using var dlg = new SaveFileDialog
                    {
                        Title = "解密导出到…",
                        FileName = leaf,
                        Filter = "所有文件 (*.*)|*.*",
                    };
                    if (dlg.ShowDialog(form) != DialogResult.OK) throw new Exception("已取消");
                    VaultFile.ExtractFile(vaultPath, master!, entry, dlg.FileName);
                    Logger.Write("文件", $"解密导出：{entry} → {dlg.FileName}");
                    return new { path = dlg.FileName };
                }

                case "decryptFolder":
                {
                    RequireUnlocked();
                    string dirPath = SafeEntryPath(Join(args, "cwd", "name"), false);
                    using var dlg = new FolderBrowserDialog
                    {
                        Description = "选择解密导出的目标文件夹",
                        ShowNewFolderButton = true,
                    };
                    if (dlg.ShowDialog(form) != DialogResult.OK) throw new Exception("已取消");
                    string prefix = dirPath + "/";
                    var files = VaultFile.ListEntries(vaultPath)
                        .Where(x => x.IsFile && x.Name.StartsWith(prefix, StringComparison.Ordinal))
                        .ToList();
                    foreach (var f in files)
                    {
                        string rel = f.Name.Substring(prefix.Length).Replace('/', Path.DirectorySeparatorChar);
                        string dest = Path.Combine(dlg.SelectedPath, rel);
                        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                        VaultFile.ExtractFile(vaultPath, master!, f.Name, dest);
                    }
                    Logger.Write("文件", $"解密导出文件夹：{dirPath}（{files.Count} 个文件）");
                    return new { count = files.Count };
                }

                case "windowDrag":
                    // 网页顶栏按住并拖动 → 进入系统窗口拖动循环（支持贴边吸附）
                    form.BeginDrag();
                    return new { ok = true };

                case "windowResize":
                    form.BeginResize(S(args, "edge"));
                    return new { ok = true };

                case "windowAction":
                    form.WindowAction(S(args, "action"));
                    return new { ok = true };

                case "pasteFromClipboard":
                {
                    // 从系统剪贴板导入（资源管理器里复制/剪切的文件/文件夹 → 加密进保险库）
                    RequireUnlocked();
                    string cwd = SafeEntryPath(S(args, "cwd"));
                    var files = new List<string>();
                    bool isMove = false;
                    try
                    {
                        var data = Clipboard.GetDataObject();
                        if (data != null && data.GetDataPresent(DataFormats.FileDrop))
                        {
                            if (data.GetData(DataFormats.FileDrop) is string[] arr)
                                files.AddRange(arr.Where(x => !string.IsNullOrEmpty(x)));
                            var eff = data.GetData("Preferred DropEffect");   // 资源管理器“剪切”标记为 Move
                            if (eff is System.IO.MemoryStream ms)
                            {
                                var buf = new byte[4];
                                ms.Position = 0;
                                ms.Read(buf, 0, 4);
                                isMove = BitConverter.ToInt32(buf, 0) == 1;
                            }
                        }
                    }
                    catch (Exception ex) { throw new Exception("读取系统剪贴板失败：" + Clean(ex.Message, 120)); }
                    if (files.Count == 0) throw new Exception("系统剪贴板里没有可导入的文件");
                    var before = SnapshotEntries();
                    var srcFiles = files.Where(f => File.Exists(f)).ToList();
                    var srcDirs = files.Where(d => Directory.Exists(d)).ToList();
                    foreach (var f in srcFiles) VaultFile.ImportFiles(vaultPath, master!, new[] { f }, cwd);
                    foreach (var d in srcDirs) VaultFile.ImportDirectory(vaultPath, master!, d, cwd);
                    var added = NewEntries(before)
                        .Where(x => x.IsFile)
                        .Select(x => new
                        {
                            relPath = cwd.Length == 0 ? x.Name
                                : (x.Name.StartsWith(cwd + "/", StringComparison.Ordinal) ? x.Name.Substring(cwd.Length + 1) : x.Name),
                            ext = ExtOf(x.Leaf),
                            size = x.PlainLength,
                            ctime = Fmt(x.Created),
                            mtime = Fmt(x.Modified),
                        })
                        .ToList();
                    if (isMove)
                    {
                        foreach (var f in srcFiles) { try { File.Delete(f); } catch { } }
                        foreach (var d in srcDirs) { try { Utils.DeleteTreeRobust(d); } catch { } }
                    }
                    Logger.Write("文件", $"从系统剪贴板{(isMove ? "剪切" : "复制")}导入 {added.Count} 个文件（{(cwd.Length == 0 ? "根目录" : cwd)}）");
                    return new { entries = added, count = added.Count, moved = isMove };
                }

                case "copyToClipboard":
                {
                    // 把保险库内选中的文件/文件夹解密到临时目录并放入系统剪贴板（支持多选，可一起粘贴到资源管理器）
                    RequireUnlocked();
                    string cwd = SafeEntryPath(S(args, "cwd"));
                    var names = S(args, "names").Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim('\r', ' ')).Where(x => x.Length > 0).ToList();
                    if (names.Count == 0) names.Add(S(args, "name"));
                    var all = VaultFile.ListEntries(vaultPath);
                    string clipRoot = Path.Combine(Path.GetTempPath(), "DH-BOX", "clip", Guid.NewGuid().ToString("N"));
                    Directory.CreateDirectory(clipRoot);
                    var col = new System.Collections.Specialized.StringCollection();
                    long total = 0;
                    foreach (var nm in names)
                    {
                        string entry = SafeEntryPath(cwd.Length == 0 ? nm : cwd + "/" + nm, false);
                        bool isDir = all.Any(x => x.Name == entry && !x.IsFile);
                        if (!isDir && !all.Any(x => x.Name == entry && x.IsFile)) continue;
                        string leaf = entry.Substring(entry.LastIndexOf('/') + 1);
                        string dest = Path.Combine(clipRoot, SafeName(leaf));
                        if (isDir)
                        {
                            Directory.CreateDirectory(dest);
                            string prefix = entry + "/";
                            foreach (var f in all.Where(x => x.IsFile && x.Name.StartsWith(prefix, StringComparison.Ordinal)))
                            {
                                string rel = f.Name.Substring(prefix.Length).Replace('/', Path.DirectorySeparatorChar);
                                string target = Path.Combine(dest, rel);
                                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                                VaultFile.ExtractFile(vaultPath, master!, f.Name, target);
                            }
                        }
                        else
                        {
                            VaultFile.ExtractFile(vaultPath, master!, entry, dest);
                        }
                        col.Add(dest);
                        try { total += isDir ? Directory.GetFiles(dest, "*", SearchOption.AllDirectories).Sum(x => new FileInfo(x).Length) : new FileInfo(dest).Length; }
                        catch { }
                    }
                    if (col.Count == 0) throw new Exception("保险库中找不到该条目");
                    try { Clipboard.SetFileDropList(col); }
                    catch (Exception ex) { throw new Exception("写入系统剪贴板失败：" + Clean(ex.Message, 120)); }
                    Logger.Write("文件", $"已复制 {col.Count} 项到系统剪贴板（明文临时副本，锁定后自动清理）");
                    return new { ok = true, local = col[0], count = col.Count, size = total };
                }
                case "fileIcons":
                {
                    // 返回扩展名 → 系统默认图标（data:image/png;base64）
                    var exts = S(args, "exts").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                    var result = new Dictionary<string, string>();
                    foreach (var ext in exts)
                    {
                        string key = ext.Length == 0 ? "__file__" : ext.ToLowerInvariant();
                        if (!iconCache.TryGetValue(key, out var b64))
                        {
                            b64 = GetShellIconBase64(key);
                            iconCache[key] = b64;
                        }
                        result[key] = b64;
                    }
                    return new { icons = result };
                }

                case "setTheme":
                    // 网页主题切换 → 窗口标题栏跟随深浅（沉浸式深色标题栏）
                    form.ApplyWindowTheme(S(args, "theme") == "dark");
                    return new { ok = true };

                case "ping":
                    return new { pong = true };

                case "jsError":
                {
                    // 前端 JS 运行时错误 → 写入 C# 日志（排障用；截断并清理换行，防日志注入）
                    string m = Clean(S(args, "message"), 500);
                    string src = Clean(S(args, "src"), 200);
                    string line = Clean(S(args, "line"), 12), col = Clean(S(args, "col"), 12);
                    string stack = Clean(S(args, "stack"), 1000);
                    Logger.Write("界面错误", $"{m} @ {src}:{line}:{col}" + (stack.Length > 0 ? " | " + stack : ""));
                    return new { ok = true };
                }

                case "screenshot":
                {
                    // 调试功能：仅在设置了 DHBOX_SHOT 环境变量时可用，且只允许写入临时目录
                    string? shot = Environment.GetEnvironmentVariable("DHBOX_SHOT");
                    if (string.IsNullOrEmpty(shot)) throw new Exception("调试截图功能未启用");
                    string path = Path.GetFullPath(S(args, "path"));
                    string tempRoot = Path.GetFullPath(Path.GetTempPath());
                    if (!path.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase))
                        throw new Exception("调试截图只允许写入临时目录");
                    using var ms = new MemoryStream();
                    await form.View.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, ms);
                    File.WriteAllBytes(path, ms.ToArray());
                    return new { path, bytes = ms.Length };
                }

                default:
                    Logger.Write("安全", "已拒绝未知桥接命令：" + Clean(cmd, 64));
                    throw new Exception("未知命令：" + Clean(cmd, 64));
            }
        }

        /* ================= 状态（加密存储） ================= */

        private void WriteState(string stateJson)
        {
            string tmpDir = Path.Combine(Path.GetTempPath(), "DH-BOX");
            Directory.CreateDirectory(tmpDir);
            string tmp = Path.Combine(tmpDir, StateEntry);
            try
            {
                File.WriteAllText(tmp, stateJson, new UTF8Encoding(false));
                var names = new HashSet<string>(VaultFile.ListEntries(vaultPath).Select(x => x.Name));
                if (names.Contains(StateEntry))
                    VaultFile.ReplaceFileFrom(vaultPath, master!, StateEntry, tmp);
                else
                    VaultFile.ImportFiles(vaultPath, master!, new[] { tmp }, "");
            }
            finally
            {
                try { File.Delete(tmp); } catch { }   // 明文临时文件用完即删
            }
        }

        private string ReadStateJson()
        {
            if (master == null) return "{}";
            var names = new HashSet<string>(VaultFile.ListEntries(vaultPath).Select(x => x.Name));
            if (!names.Contains(StateEntry)) return "{}";
            string tmp = Path.Combine(Path.GetTempPath(), "DH-BOX", "state-read.json");
            Directory.CreateDirectory(Path.GetDirectoryName(tmp)!);
            VaultFile.ExtractFile(vaultPath, master, StateEntry, tmp);
            try { return File.ReadAllText(tmp, Encoding.UTF8); }
            finally { try { File.Delete(tmp); } catch { } }   // 明文临时文件用完即删
        }

        private object LoadStateObject()
        {
            try { return json.DeserializeObject(ReadStateJson()) ?? new Dictionary<string, object>(); }
            catch { return new Dictionary<string, object>(); }
        }

        /* ================= 校验与辅助 ================= */

        private void RequireUnlocked()
        {
            if (master == null) throw new Exception("保险库处于锁定状态，请先解锁");
        }

        /// <summary>来源白名单：只信任本地界面站点（dhbox.local 映射到 web 目录）。</summary>
        private static bool IsTrustedSource(string? source)
            => !string.IsNullOrEmpty(source) &&
               source!.StartsWith("https://dhbox.local", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// 条目路径白名单校验：必须是容器内相对路径；逐段检查（长度、禁止 . 与 ..、禁止系统保留条目、
        /// 禁止控制字符与非法字符）；限制总长度与层数。
        /// </summary>
        private static string SafeEntryPath(string path, bool allowEmpty = true)
        {
            if (path.Length == 0)
            {
                if (allowEmpty) return path;
                throw new Exception("参数不合法：路径为空");
            }
            if (path.Length > PathMaxLength) throw new Exception("参数不合法：路径过长");
            if (path.StartsWith("/") || path.Contains('\\') || path.Contains(':') || path.Contains('\0'))
                throw new Exception("参数不合法：路径格式错误");
            var segs = path.Split('/');
            if (segs.Length > PathMaxSegments) throw new Exception("参数不合法：目录层级过深");
            foreach (var seg in segs)
            {
                if (seg.Length == 0 || seg.Length > 255) throw new Exception("参数不合法：路径段长度错误");
                if (seg == "." || seg == "..") throw new Exception("参数不合法：禁止相对路径段");
                if (seg == StateEntry) throw new Exception("该条目为系统保留项，不能操作");
                foreach (char c in seg)
                    if (c < 32 || "\\/:*?\"<>|".IndexOf(c) >= 0) throw new Exception("参数不合法：路径含非法字符");
            }
            return path;
        }

        /// <summary>单段名称校验（重命名等场景）。</summary>
        private static string SafeLeaf(string name)
        {
            SafeEntryPath(name, false);
            if (name.Contains('/')) throw new Exception("参数不合法：名称不能包含 /");
            return name;
        }

        /// <summary>容器中是否存在该条目（含其子树中的条目）。</summary>
        private bool EntryExists(string entryPath)
            => VaultFile.ListEntries(vaultPath)
                .Any(x => x.Name == entryPath || x.Name.StartsWith(entryPath + "/", StringComparison.Ordinal));

        /// <summary>日志输出的清洗：去掉换行（防日志注入）并截断长度。</summary>
        private static string Clean(string s, int max)
        {
            s = s.Replace('\r', ' ').Replace('\n', ' ');
            return s.Length <= max ? s : s.Substring(0, max) + "…";
        }

        private HashSet<string> SnapshotEntries()
            => new HashSet<string>(VaultFile.ListEntries(vaultPath).Select(x => x.Name));

        private List<VaultEntry> NewEntries(HashSet<string> before)
            => VaultFile.ListEntries(vaultPath).Where(x => !before.Contains(x.Name)).ToList();

        private static object FileInfoObj(VaultEntry en) => new
        {
            name = en.Leaf,
            ext = ExtOf(en.Leaf),
            size = en.PlainLength,
            ctime = Fmt(en.Created),
            mtime = Fmt(en.Modified),
        };

        private static string S(Dictionary<string, object> args, string key)
            => args.TryGetValue(key, out var v) && v != null ? v.ToString() ?? "" : "";

        private static string Join(Dictionary<string, object> args, string cwdKey, string nameKey)
        {
            string cwd = S(args, cwdKey), name = S(args, nameKey);
            return cwd.Length == 0 ? name : cwd + "/" + name;
        }

        private static string ParentOf(string entryPath)
        {
            int i = entryPath.LastIndexOf('/');
            return i < 0 ? "" : entryPath.Substring(0, i);
        }

        private static string ExtOf(string leaf)
        {
            int i = leaf.LastIndexOf('.');
            return i > 0 && i < leaf.Length - 1 ? leaf.Substring(i + 1).ToLowerInvariant() : "";
        }

        private static string Fmt(DateTime t) => t.ToString("yyyy-MM-dd HH:mm");

        /// <summary>临时文件名用的短哈希（非加密用途，仅用于避免同名冲突）。</summary>
        private static string ShortHash(string s)
        {
            using var sha = SHA256.Create();
            var h = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            return h[0].ToString("x2") + h[1].ToString("x2") + h[2].ToString("x2") + h[3].ToString("x2");
        }

        private static string SafeName(string leaf)
        {
            var sb = new StringBuilder(leaf.Length);
            foreach (char c in leaf)
                sb.Append(Array.IndexOf(Path.GetInvalidFileNameChars(), c) >= 0 ? '_' : c);
            return sb.ToString();
        }

        /// <summary>清理剪贴板临时明文副本目录（锁定/退出时调用）。</summary>
        private static void CleanClipCache()
        {
            try { Utils.DeleteTreeRobust(Path.Combine(Path.GetTempPath(), "DH-BOX", "clip")); }
            catch { }
        }

        /// <summary>取系统默认图标（kind：文件扩展名、"__dir__" 或 "__file__"），转为 base64 PNG。</summary>
        private static string GetShellIconBase64(string kind)
        {
            try
            {
                var shfi = new SHFILEINFO();
                uint attr = 0x80;                       // FILE_ATTRIBUTE_NORMAL
                string path = "file." + kind;
                if (kind == "__dir__") { attr = 0x10; path = "folder"; }   // FILE_ATTRIBUTE_DIRECTORY
                uint flags = 0x00000100 | 0x10;         // SHGFI_ICON | SHGFI_USEFILEATTRIBUTES（按扩展名取，不访问磁盘）
                SHGetFileInfo(path, attr, ref shfi, (uint)Marshal.SizeOf(typeof(SHFILEINFO)), flags);
                if (shfi.hIcon == IntPtr.Zero) return "";
                try
                {
                    using var ico = (Icon)Icon.FromHandle(shfi.hIcon).Clone();
                    using var bmp = ico.ToBitmap();
                    using var ms = new MemoryStream();
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
                }
                finally { DestroyIcon(shfi.hIcon); }
            }
            catch { return ""; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
            public string szTypeName;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes,
            ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        /// <summary>读取参数里的字符串数组。</summary>
        private static List<string> SList(Dictionary<string, object> args, string key)
            => args.TryGetValue(key, out var v) && v is System.Collections.ArrayList arr
                ? arr.Cast<object>().Select(x => x?.ToString() ?? "").Where(x => x.Length > 0).ToList()
                : new List<string>();

        private static string EnsureOpenCache()
        {
            string dir = Path.Combine(Path.GetTempPath(), "DH-BOX", "open");
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void CleanOpenCache()
        {
            try { Utils.DeleteTreeRobust(Path.Combine(Path.GetTempPath(), "DH-BOX", "open")); }
            catch { }
        }

        /// <summary>把被编辑过的临时解密文件写回保险库（重新按 AES-256 加密入库）。</summary>
        private void FlushOpenedFiles()
        {
            if (master == null) return;
            foreach (var kv in openedFiles.ToList())
            {
                try
                {
                    if (File.Exists(kv.Value.Local) &&
                        File.GetLastWriteTimeUtc(kv.Value.Local) > kv.Value.At.AddSeconds(1))
                    {
                        VaultFile.ReplaceFileFrom(vaultPath, master, kv.Key, kv.Value.Local);
                        Logger.Write("文件", "已写回修改：" + kv.Key);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Write("文件", "写回失败：" + kv.Key + "：" + Clean(ex.Message, 200));
                }
            }
            openedFiles.Clear();
        }

        /// <summary>宿主退出时调用：写回改动 → 清理临时明文 → 清除内存密钥。</summary>
        public void Shutdown()
        {
            try { FlushOpenedFiles(); } catch { }
            CleanOpenCache();
            CleanClipCache();
            master?.Wipe();
            master = null;
        }
    }
}
