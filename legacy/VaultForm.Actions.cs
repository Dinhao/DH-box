using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace SecretVault
{
    /// <summary>
    /// 主窗口的文件操作 —— 完全按照 cipherbox-ui.html 前端实现：
    ///   右键菜单结构与文案一致（打开/预览、复制、剪切、粘贴[仅文件夹]、重命名、解密、删除、属性；
    ///   空白处：新建文件夹、导入文件…、导入文件夹…、粘贴、刷新、保险库属性）；
    ///   操作反馈统一 toast（已复制「x」/ 已移动「x」/ 请选择一个未来的截止时刻 等前端文案）；
    ///   名称校验与前端一致（请输入文件夹名称 / 名称不能包含 \ / : * ? " < > | 字符 / 已存在同名文件夹）；
    ///   属性弹窗字段与前端一致（位置 = DH-BOX / 路径）。
    ///   说明：“解密”在真实程序中实现为“导出明文副本到本机”（保险库内文件本体始终为 AES-256 加密存储）；
    ///   “导入文件 / 导入文件夹”为前端未定义但真实程序必需（前端没有把文件放进保险库的入口）。
    /// </summary>
    public partial class VaultForm
    {
        /// <summary>打开缓存目录：解密到这里的文件用系统默认程序打开，锁定/退出时清理。</summary>
        internal static string OpenCacheRoot => Path.Combine(Path.GetTempPath(), "DH-BOX", "open");

        internal VaultEntry? SelectedEntry => Entries.FirstOrDefault(x => x.Name == SelectedName);

        /// <summary>目录标签（前端 dirLabel）：DH-BOX / 段 / 段（根目录为 “DH-BOX /”）。</summary>
        internal string DirLabel()
            => Cwd.Length == 0 ? "DH-BOX /" : "DH-BOX / " + Cwd.Replace("/", " / ");

        // ==================== 打开 ====================

        private void OpenSelected()
        {
            var e = SelectedEntry;
            if (e == null) return;
            if (!e.IsFile) { Navigate(e.Name); return; }
            OpenFileEntry(e);
        }

        /// <summary>解密一个文件并用系统默认程序打开（前端“打开 / 预览”）。</summary>
        internal void OpenFileEntry(VaultEntry e)
        {
            try
            {
                Directory.CreateDirectory(OpenCacheRoot);
                string dir = Path.Combine(OpenCacheRoot, VaultIds.Hash8(e.Name));
                Directory.CreateDirectory(dir);
                string local = Path.Combine(dir, e.Leaf);
                VaultFile.ExtractFile(VaultPath, Master, e.Name, local);
                OpenedFiles[e.Name] = (local, DateTime.Now);
                Logger.Write("打开", $"打开文件：{e.Leaf}（{DirLabel()}）");
                Process.Start(new ProcessStartInfo(local) { UseShellExecute = true });
                Toast($"已打开文件「{e.Leaf}」", true);
            }
            catch (Exception ex)
            {
                Logger.Write("打开", $"文件打开失败：{e.Leaf}（{ex.Message}）");
                Toast($"文件打开失败：{e.Leaf}", false);
            }
        }

        /// <summary>把本机被修改过的已打开文件写回保险库（退出 / 锁定时调用）。</summary>
        internal void FlushOpenedFiles(bool showSummary)
        {
            int saved = 0;
            foreach (var kv in OpenedFiles.ToList())
            {
                var (local, openedAt) = kv.Value;
                try
                {
                    if (!File.Exists(local)) continue;
                    if (File.GetLastWriteTime(local) <= openedAt.AddSeconds(1)) continue; // 未修改
                    VaultFile.ReplaceFileFrom(VaultPath, Master, kv.Key, local);
                    saved++;
                    Logger.Write("回写", $"修改文件：{kv.Key}（已写回保险库 {HumanSize(new FileInfo(local).Length)}）");
                }
                catch (Exception ex)
                {
                    Logger.Write("回写", $"回写失败：{kv.Key}（{ex.Message}）");
                }
            }
            if (saved > 0)
            {
                ReloadEntries();
                RenderList();
                UpdateStatus();
                if (showSummary) Toast($"已把 {saved} 个修改过的文件写回保险库", true);
            }
        }

        /// <summary>清理打开文件的临时解密目录。</summary>
        internal static void CleanOpenCache()
        {
            try { if (Directory.Exists(OpenCacheRoot)) Directory.Delete(OpenCacheRoot, true); } catch { }
        }

        // ==================== 导入（前端未定义，真实程序必需） ====================

        private void DoImportFiles()
        {
            using var dlg = new OpenFileDialog { Title = "选择要导入保险库的文件", Multiselect = true, Filter = "所有文件 (*.*)|*.*" };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                int n = VaultFile.ImportFiles(VaultPath, Master, dlg.FileNames, Cwd);
                Logger.Write("导入", $"导入 {n} 个文件到 {DirLabel()}");
                ReloadEntries();
                RenderTree();
                RenderList();
                UpdateStatus();
                Toast($"已导入 {n} 个文件", true);
            }
            catch (Exception ex) { Toast("导入失败：" + ex.Message, false); }
        }

        private void DoImportFolder()
        {
            using var dlg = new FolderBrowserDialog { Description = "选择要导入保险库的文件夹（保留目录结构）", ShowNewFolderButton = false };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                int n = VaultFile.ImportDirectory(VaultPath, Master, dlg.SelectedPath, Cwd);
                Logger.Write("导入", $"导入文件夹：{Path.GetFileName(dlg.SelectedPath)}（{n} 个文件）（{DirLabel()}）");
                ReloadEntries();
                RenderTree();
                RenderList();
                UpdateStatus();
                Toast($"已导入文件夹（{n} 个文件）", true);
            }
            catch (Exception ex) { Toast("导入失败：" + ex.Message, false); }
        }

        // ==================== 解密（导出明文副本到本机） ====================

        /// <summary>“解密”：把选中条目导出为明文副本到本机（文件另存为 / 文件夹选择目标目录）。</summary>
        private void DoDecrypt()
        {
            var e = SelectedEntry;
            if (e == null) { Toast("请先选择要解密的项目", false); return; }
            try
            {
                if (e.IsFile)
                {
                    using var dlg = new SaveFileDialog { Title = "解密到本机", FileName = e.Leaf, Filter = "所有文件 (*.*)|*.*" };
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    VaultFile.ExtractFile(VaultPath, Master, e.Name, dlg.FileName);
                    Logger.Write("解密", $"解密：{e.Leaf} → {dlg.FileName}（{DirLabel()}）");
                    Toast($"「{e.Leaf}」已解密导出", true);
                    return;
                }

                using var pick = new FolderBrowserDialog { Description = "选择解密导出目标文件夹", ShowNewFolderButton = true };
                if (pick.ShowDialog(this) != DialogResult.OK) return;
                string baseDir = Path.Combine(pick.SelectedPath, e.Leaf);
                Directory.CreateDirectory(baseDir);
                int n = 0;
                foreach (var sub in Entries.Where(x => !x.IsFile && x.Name.StartsWith(e.Name + "/", StringComparison.OrdinalIgnoreCase)))
                {
                    string rel = sub.Name.Substring(e.Name.Length + 1).Replace('/', '\\');
                    Directory.CreateDirectory(Path.Combine(baseDir, rel));
                }
                foreach (var f in Entries.Where(x => x.IsFile && x.Name.StartsWith(e.Name + "/", StringComparison.OrdinalIgnoreCase)))
                {
                    string rel = f.Name.Substring(e.Name.Length + 1).Replace('/', '\\');
                    VaultFile.ExtractFile(VaultPath, Master, f.Name, Path.Combine(baseDir, rel));
                    n++;
                }
                Logger.Write("解密", $"解密：{e.Leaf}（{n} 个文件）→ {pick.SelectedPath}（{DirLabel()}）");
                Toast($"「{e.Leaf}」已解密导出（{n} 个文件）", true);
            }
            catch (Exception ex) { Toast("解密失败：" + ex.Message, false); }
        }

        // ==================== 新建 / 重命名 / 删除 / 属性 ====================

        private void DoNewFolder()
        {
            var name = InputDialog.Show(this, "📁 新建文件夹", "文件夹名称", "新建文件夹", "例如：工作资料");
            if (name == null) return;
            if (name.Length == 0) { Toast("请输入文件夹名称", false); return; }
            if (name.IndexOfAny(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0)
            { Toast("名称不能包含 \\ / : * ? \" < > | 字符", false); return; }
            if (ChildrenOf(Cwd).Any(c => !c.IsFile && c.Leaf.Equals(name, StringComparison.OrdinalIgnoreCase)))
            { Toast("已存在同名文件夹", false); return; }
            try
            {
                VaultFile.CreateFolder(VaultPath, Master, Cwd, name);
                Logger.Write("新建文件夹", $"创建文件夹：{name}（{DirLabel()}）");
                ReloadEntries();
                RenderTree();
                RenderList();
                UpdateStatus();
                Toast($"已创建文件夹「{name}」", true);
            }
            catch (Exception ex) { Toast("创建失败：" + ex.Message, false); }
        }

        private void DoRename()
        {
            var e = SelectedEntry;
            if (e == null) { Toast("请先选择要重命名的项目", false); return; }
            var name = InputDialog.Show(this, "✏️ 重命名", "新名称", e.Leaf, null);
            if (name == null) return;
            if (name.Length == 0) { Toast("名称不能为空", false); return; }
            if (name.IndexOfAny(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0)
            { Toast("名称不能包含 \\ / : * ? \" < > | 字符", false); return; }
            if (name == e.Leaf) return;
            if (ChildrenOf(e.ParentDir).Any(c => c.Name != e.Name && c.IsFile == e.IsFile
                && c.Leaf.Equals(name, StringComparison.OrdinalIgnoreCase)))
            { Toast("已存在同名项目", false); return; }
            try
            {
                string oldName = e.Leaf;
                VaultFile.RenameEntry(VaultPath, Master, e.Name, name);
                Logger.Write("重命名", $"重命名：{oldName} → {name}（{DirLabel()}）");
                ReloadEntries();
                RenderTree();
                RenderList();
                UpdateStatus();
                var renamed = Entries.FirstOrDefault(x => x.ParentDir == e.ParentDir && x.Leaf == name);
                SelectedName = renamed?.Name ?? "";
                RenderList();
                Toast($"已重命名为「{name}」", true);
            }
            catch (Exception ex) { Toast("重命名失败：" + ex.Message, false); }
        }

        private void DoDelete()
        {
            var e = SelectedEntry;
            if (e == null) { Toast("请先选择要删除的项目", false); return; }
            string body = e.IsFile
                ? $"确定删除文件「{e.Leaf}」吗？\n\n此操作不可恢复，删除后不会进入回收站。"
                : $"确定删除文件夹「{e.Leaf}」及其中的全部内容吗？\n\n此操作不可恢复，删除后不会进入回收站。";
            if (ConfirmDialog.Show(this, "🗑️ 删除", body, "删除", danger: true) != DialogResult.OK) return;
            try
            {
                VaultFile.DeleteEntries(VaultPath, Master, new[] { e.Name });
                Logger.Write("删除", $"删除：{e.Leaf}（{DirLabel()}）");
                if (ClipItem != null && ClipItem.Name == e.Name) ClearClipboard();
                SelectedName = "";
                ReloadEntries();
                RenderTree();
                RenderList();
                UpdateStatus();
                Toast($"已删除「{e.Leaf}」", true);
            }
            catch (Exception ex) { Toast("删除失败：" + ex.Message, false); }
        }

        /// <summary>属性弹窗（字段与前端一致）。</summary>
        private void DoShowProps()
        {
            var e = SelectedEntry;
            if (e == null) { ShowVaultProps(); return; }
            var rows = new List<(string, string)>
            {
                ("名称", e.Leaf),
                ("类型", e.IsFile ? FileTypeName(e.Leaf) : "文件夹"),
                ("位置", e.ParentDir.Length == 0 ? "DH-BOX /" : "DH-BOX / " + e.ParentDir.Replace("/", " / ")),
            };
            if (e.IsFile)
            {
                rows.Add(("大小", $"{HumanSize(e.PlainLength)}（{e.PlainLength} 字节）"));
                int dot = e.Leaf.LastIndexOf('.');
                rows.Add(("格式", dot >= 0 ? e.Leaf.Substring(dot + 1).ToUpperInvariant() : "—"));
            }
            else
            {
                rows.Add(("包含", $"{Entries.Count(x => x.ParentDir == e.Name)} 个项目"));
                rows.Add(("占用空间", HumanSize(DirSize(e.Name))));
            }
            rows.Add(("加密状态", "🔒 已加密（AES-256）"));
            rows.Add(("创建时间", e.Created == DateTime.MinValue ? "—" : e.Created.ToString("yyyy-MM-dd HH:mm:ss")));
            rows.Add(("修改时间", e.Modified == DateTime.MinValue ? "—" : e.Modified.ToString("yyyy-MM-dd HH:mm:ss")));
            PropsDialog.Show(this, "ℹ️ 属性", rows);
        }

        private void ShowVaultProps()
        {
            var fi = new FileInfo(VaultPath);
            PropsDialog.Show(this, "ℹ️ 属性", new List<(string, string)>
            {
                ("名称", "我的密库（根目录）"),
                ("类型", "文件夹"),
                ("位置", "DH-BOX /"),
                ("包含", $"{Entries.Count(e => e.ParentDir.Length == 0)} 个项目"),
                ("占用空间", HumanSize(Entries.Where(e => e.IsFile).Sum(e => e.PlainLength))),
                ("加密状态", "🔒 已加密（AES-256）"),
                ("创建时间", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")),
                ("修改时间", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")),
            });
        }

        // ==================== 复制 / 剪切 / 粘贴（前端为单条剪贴板） ====================

        private void DoCopy()
        {
            var e = SelectedEntry;
            if (e == null) { Toast("请先选择要复制的项目", false); return; }
            ClipMode = "copy";
            ClipItem = e;
            ClipFromDir = e.ParentDir;
            UpdateStatus();
            Toast($"已复制「{e.Leaf}」", true);
        }

        private void DoCut()
        {
            var e = SelectedEntry;
            if (e == null) { Toast("请先选择要剪切的项目", false); return; }
            ClipMode = "cut";
            ClipItem = e;
            ClipFromDir = e.ParentDir;
            UpdateStatus();
            Toast($"已剪切「{e.Leaf}」，请到目标文件夹粘贴", true);
        }

        private void DoPasteTo(string destDir)
        {
            if (ClipItem == null) { Toast("剪贴板为空", false); return; }
            var item = ClipItem;
            // 原位置已不存在（来源目录被删除）
            if (ClipFromDir.Length > 0 && !Entries.Any(x => !x.IsFile && x.Name == ClipFromDir))
            { ClearClipboard(); Toast("原位置已不存在", false); return; }
            // 项目已被移除
            if (!Entries.Any(x => x.Name == item.Name))
            { ClearClipboard(); Toast("项目已被移除", false); return; }

            // 目录防套娃（不能移入自身或自身子目录）
            if (!item.IsFile && (destDir == item.Name || destDir.StartsWith(item.Name + "/", StringComparison.OrdinalIgnoreCase)))
            {
                Toast("不能把文件夹移动到它自身或其子文件夹中", false);
                return;
            }
            // 原位置粘贴 = 无操作
            if (ClipMode == "cut" && destDir == item.ParentDir)
            {
                ClearClipboard();
                return;
            }
            try
            {
                string destPath = destDir.Length == 0 ? "根目录" : destDir;
                if (ClipMode == "cut")
                {
                    VaultFile.MoveEntries(VaultPath, Master, new[] { item.Name }, destDir);
                    Logger.Write("移动", $"移动：{item.Leaf} → {destPath}");
                    ClearClipboard();
                    ReloadEntries();
                    RenderTree();
                    RenderList();
                    UpdateStatus();
                    Toast($"已移动「{item.Leaf}」", true);
                }
                else
                {
                    VaultFile.CopyEntries(VaultPath, Master, new[] { item.Name }, destDir);
                    Logger.Write("复制", $"复制：{item.Leaf} → {destPath}");
                    ReloadEntries();
                    RenderTree();
                    RenderList();
                    UpdateStatus();
                    Toast($"已粘贴「{item.Leaf}」", true);
                }
            }
            catch (Exception ex) { Toast("粘贴失败：" + ex.Message, false); }
        }

        private void ClearClipboard()
        {
            ClipMode = "";
            ClipItem = null;
            ClipFromDir = "";
            UpdateStatus();
        }

        // ==================== 右键菜单 / 列设置 ====================

        private void ShowContextMenu(Point at)
        {
            var e = SelectedEntry;
            var menu = new ContextMenuStrip { BackColor = Theme.Card, ForeColor = Theme.Text };
            if (e != null)
            {
                if (e.IsFile) menu.Items.Add("🔍 打开 / 预览", null, (s, a) => OpenFileEntry(e));
                else menu.Items.Add("📂 打开", null, (s, a) => Navigate(e.Name));
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("📋 复制", null, (s, a) => DoCopy());
                menu.Items.Add("✂️ 剪切", null, (s, a) => DoCut());
                menu.Items.Add("📥 粘贴", null, (s, a) => DoPasteTo(e.Name)).Enabled = ClipItem != null && !e.IsFile;
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("✏️ 重命名", null, (s, a) => DoRename());
                menu.Items.Add("🔓 解密（导出明文副本）", null, (s, a) => DoDecrypt());
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("🗑️ 删除", null, (s, a) => DoDelete()).ForeColor = Theme.Danger;
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("ℹ️ 属性", null, (s, a) => DoShowProps());
            }
            else
            {
                menu.Items.Add("📁 新建文件夹", null, (s, a) => DoNewFolder());
                menu.Items.Add("📤 导入文件…", null, (s, a) => DoImportFiles());
                menu.Items.Add("📂 导入文件夹…", null, (s, a) => DoImportFolder());
                menu.Items.Add("📥 粘贴", null, (s, a) => DoPasteTo(Cwd)).Enabled = ClipItem != null;
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("🔄 刷新", null, (s, a) =>
                {
                    ReloadEntries();
                    RenderTree();
                    RenderList();
                    UpdateStatus();
                    Toast("已刷新", true);
                });
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("ℹ️ 保险库属性", null, (s, a) => ShowVaultProps());
            }
            menu.Show(list.Visible ? (Control)list : emptyState, at);
        }

        /// <summary>列设置菜单（前端：勾选 = 添加列；取消勾选 = 删除列；名称列固定）。</summary>
        private void ShowColumnsMenu(Control anchor)
        {
            var menu = new ContextMenuStrip { BackColor = Theme.Card, ForeColor = Theme.Text };
            foreach (var (key, title) in new[] { ("type", "类型"), ("size", "大小"), ("mtime", "修改时间"), ("ctime", "创建时间"), ("enc", "加密状态") })
            {
                var item = new ToolStripMenuItem(title) { Checked = Cfg.Columns.Contains(key), CheckOnClick = true };
                item.CheckedChanged += (s, a) =>
                {
                    if (item.Checked) { if (!Cfg.Columns.Contains(key)) Cfg.Columns.Add(key); }
                    else Cfg.Columns.Remove(key);
                    Cfg.Save();
                    RenderList();
                };
                menu.Items.Add(item);
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("勾选 = 添加列；取消勾选 = 删除列（名称列固定）") { Enabled = false });
            menu.Show(anchor, new Point(0, anchor.Height + 4));
        }
    }

    /// <summary>单行输入弹窗（新建文件夹 / 重命名，等价前端 modal）。</summary>
    internal static class InputDialog
    {
        public static string? Show(IWin32Window owner, string title, string prompt, string defaultValue, string? placeholder)
        {
            using var f = new Form
            {
                Text = title,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                ClientSize = new Size(420, 150),
                MinimizeBox = false,
                MaximizeBox = false,
                Font = new Font("Microsoft YaHei UI", 9F),
            };
            var label = new Label { Text = prompt, Location = new Point(16, 16), AutoSize = true, Tag = "dim" };
            var box = new TextBox { Text = defaultValue, Location = new Point(16, 44), Width = 388 };
            if (placeholder != null) PlaceholderHelper.Set(box, placeholder);
            var ok = new Button { Text = "确定", DialogResult = DialogResult.OK, Location = new Point(238, 92), Size = new Size(80, 30), Tag = "primary" };
            var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, Location = new Point(324, 92), Size = new Size(80, 30) };
            f.Controls.AddRange(new Control[] { label, box, ok, cancel });
            f.AcceptButton = ok;
            f.CancelButton = cancel;
            Theme.ApplyTo(f);
            box.SelectAll();
            box.Focus();
            return f.ShowDialog(owner) == DialogResult.OK ? box.Text.Trim() : null;
        }
    }

    /// <summary>确认弹窗（删除、清空日志）。</summary>
    internal static class ConfirmDialog
    {
        public static DialogResult Show(IWin32Window owner, string title, string message, string okText, bool danger = false)
        {
            using var f = new Form
            {
                Text = title,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                ClientSize = new Size(440, 200),
                MinimizeBox = false,
                MaximizeBox = false,
                Font = new Font("Microsoft YaHei UI", 9F),
            };
            var label = new Label { Text = message, Location = new Point(16, 16), Size = new Size(408, 120), Tag = "dim" };
            var ok = new Button
            {
                Text = okText,
                DialogResult = DialogResult.OK,
                Location = new Point(240, 150),
                Size = new Size(90, 32),
                ForeColor = danger ? Theme.Danger : Theme.Text,
            };
            var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, Location = new Point(336, 150), Size = new Size(88, 32) };
            f.Controls.AddRange(new Control[] { label, ok, cancel });
            f.AcceptButton = cancel;
            f.CancelButton = cancel;
            Theme.ApplyTo(f);
            return f.ShowDialog(owner);
        }
    }

    /// <summary>属性弹窗（键值表，等价前端 propsModal）。</summary>
    internal static class PropsDialog
    {
        public static void Show(IWin32Window owner, string title, List<(string Label, string Value)> rows)
        {
            using var f = new Form
            {
                Text = title,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                ClientSize = new Size(460, 100 + Math.Min(rows.Count, 12) * 27),
                MinimizeBox = false,
                MaximizeBox = false,
                Font = new Font("Microsoft YaHei UI", 9F),
            };
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18, 14, 18, 8), ColumnCount = 2 };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100F));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            foreach (var (label, value) in rows)
            {
                int r = grid.RowCount;
                grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
                grid.Controls.Add(new Label { Text = label, AutoSize = true, Tag = "dim", Anchor = AnchorStyles.Left }, 0, r);
                grid.Controls.Add(new Label { Text = value, AutoSize = true, Anchor = AnchorStyles.Left, MaximumSize = new Size(310, 0) }, 1, r);
            }
            var close = new Button { Text = "关闭", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom, Height = 36, Tag = "primary" };
            f.Controls.Add(grid);
            f.Controls.Add(close);
            f.AcceptButton = close;
            f.CancelButton = close;
            Theme.ApplyTo(f);
            f.ShowDialog(owner);
        }
    }
}
