using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace SecretVault
{
    /// <summary>
    /// DH-BOX 主窗口 —— 完全按照 cipherbox-ui.html 前端的设计实现：
    ///   顶栏：🛡️ + DH-BOX 品牌 + 状态胶囊（保险库已解锁/已锁定）+ 🔒 锁定 / 🗂️ 主界面 / ⚙️ 设置 / 🌙；
    ///   主界面：侧栏「保险库目录」树 + 面包屑 + 工具条（返回上级/新建文件夹/粘贴/列设置 + 右侧提示）
    ///          + 文件列表（自绘：图标、名称+已加密徽标、动态列）+ 状态栏（项目数 · 占用空间 · 剪贴板 · AES-256 全盘加密）；
    ///   设置：左侧导航（修改密码 / 查看日志 / 自动锁定）+ 右侧内容；
    ///   锁定：🔒 按钮或到点自动锁定 → 全屏锁定覆盖层（输入主密码解锁后回到原界面）；
    ///   首次使用：设置主密码弹窗；文件全部在程序内查看与使用（双击解密后用系统默认程序打开）。
    /// </summary>
    public partial class VaultForm : Form
    {
        internal readonly string VaultPath;
        internal readonly AppConfig Cfg;
        internal MasterKeys Master;          // 锁定时会被清空并置空
        internal DateTime LockTargetUtc;     // 目标锁定时间戳（保存设置后立即生效）
        internal bool Locked;                // 保险库是否处于锁定状态

        // 浏览状态（与前端 state 对应）
        internal string Cwd = "";                    // 当前目录（容器内相对路径，"" = 根）
        internal List<VaultEntry> Entries = new();   // 容器条目缓存
        internal string SelectedName = "";           // 选中项名称（前端为单选）
        internal string ClipMode = "";               // "" / "copy" / "cut"
        internal VaultEntry? ClipItem;               // 剪贴板项（前端为单项）
        internal string ClipFromDir = "";            // 剪贴项来源目录

        // 已打开（解密到临时目录）的文件：条目路径 → (本地路径, 打开时间)
        internal readonly Dictionary<string, (string Local, DateTime OpenedAt)> OpenedFiles = new();

        // 界面控件
        private Panel viewMain = null!, viewSettings = null!, lockOverlay = null!;
        private TreeView tree = null!;
        private FlowLayoutPanel breadcrumb = null!, toolbar = null!;
        private ListView list = null!;
        private Label emptyState = null!, toolbarHint = null!;
        private Label statItems = null!, statSize = null!, statClip = null!;
        private Label brandSub = null!, toastLabel = null!;
        private Panel statusPill = null!;
        private Label statusPillDot = null!, statusPillText = null!;
        private Button btnTheme = null!, btnMain = null!, btnSettings = null!, btnLock = null!, btnUp = null!;
        private TextBox unlockPassBox = null!;
        private Label unlockErrLabel = null!;
        private Button unlockBtn = null!;
        private readonly ToolTip tips = new();
        private readonly Timer lockTimer = new() { Interval = 1000 };
        private readonly Timer toastTimer = new() { Interval = 2400 };
        private bool suppressTreeSelect; // 防止 RenderTree 设置选中项时递归触发 AfterSelect

        /// <summary>当前列表的列键（与 ListView 列索引对齐：索引 0=名称，其后为动态列）。</summary>
        internal string[] ColumnKeys = Array.Empty<string>();

        public VaultForm(string vaultPath, AppConfig cfg, MasterKeys? master, DateTime? lockTargetUtc)
        {
            VaultPath = vaultPath;
            Cfg = cfg;
            Master = master ?? new MasterKeys();
            Locked = master == null;
            LockTargetUtc = lockTargetUtc ?? DateTime.UtcNow.AddMinutes(Math.Max(1, Cfg.LockMinutes));

            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "DH-BOX · 文件加密保险库";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1020, 660);
            MinimumSize = new Size(860, 540);
            Font = new Font("Microsoft YaHei UI", 9F);

            BuildLayout();
            Theme.Apply(Cfg.Theme);
            Theme.ApplyTo(this);
            ApplyThemeButton();

            Load += (s, e) =>
            {
                if (Locked) ShowLockOverlay();
                else { ReloadEntries(); Navigate("", pushHistory: false); }
                UpdateStatusPill();
                lockTimer.Start();
            };
            lockTimer.Tick += (s, e) => OnLockTick();
            toastTimer.Tick += (s, e) => { toastLabel.Visible = false; toastTimer.Stop(); };
            FormClosing += (s, e) => FlushOpenedFiles(showSummary: false);
        }

        // ==================== 布局 ====================

        private void BuildLayout()
        {
            // —— 顶栏：🛡️ + 品牌 + 状态胶囊 + 锁定/主界面/设置/主题 ——
            var top = new Panel { Dock = DockStyle.Top, Height = 52, Tag = "card" };
            var brandBox = new FlowLayoutPanel
            {
                Dock = DockStyle.Left,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                FlowDirection = FlowDirection.LeftToRight,
                Padding = new Padding(14, 0, 0, 0),
            };
            var logo = new Label
            {
                Text = "🛡️",
                Font = new Font("Segoe UI Emoji", 15F),
                AutoSize = true,
                Margin = new Padding(0, 11, 8, 0),
            };
            var brand = new Label
            {
                Text = "DH-BOX",
                Font = new Font("Microsoft YaHei UI", 15F, FontStyle.Bold),
                ForeColor = Theme.Accent,
                AutoSize = true,
                Margin = new Padding(0, 10, 8, 0),
            };
            brandSub = new Label
            {
                Text = "文件加密保险库",
                AutoSize = true,
                Tag = "dim",
                Margin = new Padding(0, 20, 0, 0),
            };
            brandBox.Controls.Add(logo);
            brandBox.Controls.Add(brand);
            brandBox.Controls.Add(brandSub);

            // 状态胶囊（圆点 + 文本）
            statusPill = new Panel { AutoSize = false, Size = new Size(132, 26), Margin = new Padding(0, 13, 6, 0) };
            statusPillDot = new Label { Text = "●", AutoSize = true, Location = new Point(9, 3), Font = new Font("Microsoft YaHei UI", 8F) };
            statusPillText = new Label { Text = "保险库已解锁", AutoSize = true, Location = new Point(21, 4), Font = new Font("Microsoft YaHei UI", 8.5F) };
            statusPill.Controls.Add(statusPillDot);
            statusPill.Controls.Add(statusPillText);

            btnLock = TopButton("🔒 锁定", 72);
            btnMain = TopButton("🗂️ 主界面", 92);
            btnSettings = TopButton("⚙️ 设置", 92);
            btnTheme = TopButton("🌙", 44);
            btnLock.Click += (s, e) => LockVault("手动锁定");
            btnMain.Click += (s, e) => ShowView(settings: false);
            btnSettings.Click += (s, e) => ShowView(settings: true);
            btnTheme.Click += (s, e) => ToggleTheme();
            tips.SetToolTip(btnLock, "锁定保险库");
            tips.SetToolTip(btnMain, "主界面");
            tips.SetToolTip(btnSettings, "设置");

            var topRight = new FlowLayoutPanel
            {
                Dock = DockStyle.Right,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 10, 12, 0),
            };
            topRight.Controls.Add(statusPill);
            topRight.Controls.Add(btnLock);
            topRight.Controls.Add(btnMain);
            topRight.Controls.Add(btnSettings);
            topRight.Controls.Add(btnTheme);

            top.Controls.Add(topRight);
            top.Controls.Add(brandBox);

            // —— 内容区：主界面 / 设置 ——
            var content = new Panel { Dock = DockStyle.Fill };
            viewMain = BuildMainView();
            viewSettings = BuildSettingsView();
            content.Controls.Add(viewSettings);
            content.Controls.Add(viewMain);
            viewSettings.Visible = false;

            // —— 锁定覆盖层（全屏遮罩，居中锁卡片）——
            lockOverlay = BuildLockOverlay();

            // —— 底部 toast 提示 ——
            toastLabel = new Label
            {
                AutoSize = false,
                Size = new Size(420, 36),
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Theme.Card,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.FixedSingle,
                Visible = false,
                Tag = "toast",
                Font = new Font("Microsoft YaHei UI", 9.5F),
            };

            Controls.Add(lockOverlay);
            Controls.Add(toastLabel);
            toastLabel.BringToFront();
            lockOverlay.BringToFront();
            lockOverlay.Visible = false;
            Controls.Add(content);
            Controls.Add(top);
            Resize += (s, e) => PositionToast();
        }

        private Button TopButton(string text, int width)
            => new()
            {
                Text = text,
                AutoSize = false,
                Size = new Size(width, 32),
                Margin = new Padding(6, 0, 0, 0),
            };

        /// <summary>主界面：侧栏目录树 + 工具条 + 面包屑 + 文件列表/空状态 + 状态栏。</summary>
        private Panel BuildMainView()
        {
            var root = new Panel { Dock = DockStyle.Fill };

            // 侧栏
            var side = new Panel { Dock = DockStyle.Left, Width = 220, Padding = new Padding(8), Tag = "card" };
            var sideTitle = new Label
            {
                Text = "保险库目录",
                Dock = DockStyle.Top,
                Height = 30,
                Tag = "dim",
                Padding = new Padding(4, 6, 0, 0),
            };
            tree = new TreeView
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.None,
                HideSelection = false,
                FullRowSelect = true,
                ShowLines = false,
            };
            tree.AfterSelect += (s, e) =>
            {
                if (suppressTreeSelect) return;
                if (tree.SelectedNode?.Tag is string path) Navigate(path, pushHistory: false);
            };
            side.Controls.Add(tree);
            side.Controls.Add(sideTitle);

            // 右侧
            var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 0, 0, 0) };
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));  // 工具条
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));  // 面包屑
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 列表
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));  // 状态栏

            // 工具条：四按钮 + 右侧提示
            var toolRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
            toolRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            toolRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            toolbar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            btnUp = new Button { Text = "⬅️ 返回上级", AutoSize = true, Margin = new Padding(0, 6, 8, 6) };
            btnUp.Click += (s, e) => GoUp();
            tips.SetToolTip(btnUp, "返回上一级");
            var btnNew = new Button { Text = "📁 新建文件夹", AutoSize = true, Tag = "primary", Margin = new Padding(0, 6, 8, 6) };
            btnNew.Click += (s, e) => DoNewFolder();
            var btnPaste = new Button { Text = "📥 粘贴", AutoSize = true, Margin = new Padding(0, 6, 8, 6) };
            btnPaste.Click += (s, e) => DoPasteTo(Cwd);
            tips.SetToolTip(btnPaste, "粘贴");
            var btnCols = new Button { Text = "📋 列设置", AutoSize = true, Margin = new Padding(0, 6, 8, 6) };
            btnCols.Click += (s, e) => ShowColumnsMenu(btnCols);
            tips.SetToolTip(btnCols, "增删列");
            toolbar.Controls.AddRange(new Control[] { btnUp, btnNew, btnPaste, btnCols });
            toolbarHint = new Label
            {
                Text = "双击进入文件夹 · 右键更多操作",
                AutoSize = true,
                Tag = "faint",
                Margin = new Padding(6, 15, 8, 0),
                Font = new Font("Microsoft YaHei UI", 8.5F),
            };
            toolRow.Controls.Add(toolbar, 0, 0);
            toolRow.Controls.Add(toolbarHint, 1, 0);

            breadcrumb = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 4, 0, 0) };

            // 文件列表（自绘）+ 空状态
            var listHost = new Panel { Dock = DockStyle.Fill };
            list = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = false,
                MultiSelect = false,
                HideSelection = true,
                BorderStyle = BorderStyle.None,
                OwnerDraw = true,
            };
            list.DrawColumnHeader += (s, e) => DrawColumnHeader(e);
            list.DrawItem += (s, e) => { /* 行背景在 DrawSubItem 中统一绘制 */ };
            list.DrawSubItem += (s, e) => DrawSubItem(e);
            list.DoubleClick += (s, e) => OpenSelected();
            list.SelectedIndexChanged += (s, e) => SyncSelection();
            list.MouseUp += (s, e) => { if (e.Button == MouseButtons.Right) ShowContextMenu(new Point(e.X, e.Y)); };
            list.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) { OpenSelected(); e.Handled = true; }
                else if (e.KeyCode == Keys.Delete) { DoDelete(); e.Handled = true; }
                else if (e.KeyCode == Keys.F2) { DoRename(); e.Handled = true; }
                else if (e.KeyCode == Keys.F5) { ReloadEntries(); Navigate(Cwd, pushHistory: false); Toast("已刷新", true); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.C) { DoCopy(); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.X) { DoCut(); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.V) { DoPasteTo(Cwd); e.Handled = true; }
            };
            emptyState = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Tag = "faint",
                Visible = false,
                Text = "🗂️\r\n此文件夹为空\r\n点击上方「新建文件夹」或在此处右键开始整理",
            };
            emptyState.MouseUp += (s, e) => { if (e.Button == MouseButtons.Right) ShowContextMenu(new Point(e.X, e.Y)); };
            listHost.Controls.Add(emptyState);
            listHost.Controls.Add(list);

            // 状态栏：左侧三项 + 右侧 AES-256 全盘加密
            var statusRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var status = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(2, 4, 0, 0) };
            statItems = StatusLabel();
            statSize = StatusLabel();
            statClip = StatusLabel();
            status.Controls.AddRange(new Control[] { statItems, statSize, statClip });
            var encNote = new Label
            {
                Text = "AES-256 全盘加密",
                AutoSize = true,
                Tag = "dim",
                Margin = new Padding(6, 4, 8, 0),
                Font = new Font("Microsoft YaHei UI", 8.5F),
            };
            statusRow.Controls.Add(status, 0, 0);
            statusRow.Controls.Add(encNote, 1, 0);

            grid.Controls.Add(toolRow, 0, 0);
            grid.Controls.Add(breadcrumb, 0, 1);
            grid.Controls.Add(listHost, 0, 2);
            grid.Controls.Add(statusRow, 0, 3);

            right.Controls.Add(grid);
            right.Controls.Add(side);
            root.Controls.Add(right);
            return root;
        }

        private static Label StatusLabel()
            => new() { AutoSize = true, Tag = "dim", Margin = new Padding(0, 0, 22, 0), Font = new Font("Microsoft YaHei UI", 8.5F) };

        // ==================== 锁定覆盖层 ====================

        /// <summary>全屏锁定覆盖层（🔒 图标 + 保险库已锁定 + 主密码输入 + 解锁按钮）。</summary>
        private Panel BuildLockOverlay()
        {
            var overlay = new Panel { Dock = DockStyle.Fill, Tag = "bg" };
            var box = new TableLayoutPanel
            {
                ColumnCount = 1,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Anchor = AnchorStyles.None,
                Padding = new Padding(34, 30, 34, 30),
                Tag = "card",
            };
            box.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var logo = new Label { Text = "🔒", Font = new Font("Segoe UI Emoji", 34F), AutoSize = true, Anchor = AnchorStyles.None, Margin = new Padding(0, 0, 0, 10) };
            var title = new Label { Text = "保险库已锁定", Font = new Font("Microsoft YaHei UI", 16F, FontStyle.Bold), AutoSize = true, Anchor = AnchorStyles.None, Margin = new Padding(0, 0, 0, 6) };
            var desc = new Label { Text = "输入主密码以解锁 DH-BOX", AutoSize = true, Tag = "dim", Anchor = AnchorStyles.None, Margin = new Padding(0, 0, 0, 18) };
            unlockPassBox = new TextBox { Width = 300, UseSystemPasswordChar = true, Anchor = AnchorStyles.None, Margin = new Padding(0, 0, 0, 8) };
            unlockErrLabel = new Label { AutoSize = true, ForeColor = Theme.Danger, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, 0, 6), MaximumSize = new Size(300, 0) };
            PlaceholderHelper.Set(unlockPassBox, "主密码");
            unlockBtn = new Button { Text = "解锁", AutoSize = false, Size = new Size(300, 36), Tag = "primary", Anchor = AnchorStyles.None, Margin = new Padding(0, 4, 0, 0) };
            unlockBtn.Click += (s, e) => TryUnlockFromOverlay();
            unlockPassBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { TryUnlockFromOverlay(); e.Handled = true; e.SuppressKeyPress = true; } };

            box.Controls.Add(logo);
            box.Controls.Add(title);
            box.Controls.Add(desc);
            box.Controls.Add(unlockPassBox);
            box.Controls.Add(unlockErrLabel);
            box.Controls.Add(unlockBtn);
            overlay.Controls.Add(box);
            overlay.Resize += (s, e) =>
            {
                box.Left = Math.Max(0, (overlay.ClientSize.Width - box.Width) / 2);
                box.Top = Math.Max(0, (overlay.ClientSize.Height - box.Height) / 2);
            };
            return overlay;
        }

        /// <summary>锁定保险库：写回改动 → 清理临时文件 → 清空密钥 → 显示锁定覆盖层。</summary>
        internal void LockVault(string reason)
        {
            if (Locked) return;
            Logger.Write("锁定", reason);
            try { FlushOpenedFiles(showSummary: false); } catch { }
            CleanOpenCache();
            Locked = true;
            ShowLockOverlay();
            UpdateStatusPill();
        }

        internal void ShowLockOverlay()
        {
            unlockPassBox.Text = "";
            unlockErrLabel.Text = "";
            unlockBtn.Enabled = true;
            unlockPassBox.Enabled = true;
            lockOverlay.Visible = true;
            lockOverlay.BringToFront();
            if (LockoutPolicy.IsLocked(Cfg)) UpdateUnlockLockState();
            else unlockPassBox.Focus();
        }

        internal void HideLockOverlay()
        {
            lockOverlay.Visible = false;
            UpdateStatusPill();
        }

        /// <summary>锁定期内禁用输入并显示剩余时间（阶梯锁定）。</summary>
        private void UpdateUnlockLockState()
        {
            unlockPassBox.Enabled = false;
            unlockBtn.Enabled = false;
            unlockErrLabel.Text = $"连续输错密码触发保护：请 {LockoutPolicy.RemainingText(Cfg)} 后重试。";
        }

        /// <summary>覆盖层解锁：验证主密码（含阶梯锁定），成功后重新加载数据。</summary>
        private void TryUnlockFromOverlay()
        {
            if (LockoutPolicy.IsLocked(Cfg))
            {
                UpdateUnlockLockState();
                return;
            }
            string pwd = unlockPassBox.Text;
            if (string.IsNullOrEmpty(pwd)) { unlockErrLabel.Text = "请输入主密码"; return; }

            var mk = VaultFile.TryUnlock(VaultPath, pwd, out _);
            if (mk == null)
            {
                LockoutPolicy.OnFailure(Cfg);
                if (LockoutPolicy.IsLocked(Cfg))
                {
                    int minutes = LockoutPolicy.LockMinutes(Cfg.LockoutStage);
                    Logger.Write("解锁", $"连续 {LockoutPolicy.FailLimit} 次密码错误，已临时锁定 {minutes} 分钟（第 {Cfg.LockoutStage} 档）");
                    UpdateUnlockLockState();
                }
                else
                {
                    Logger.Write("解锁", $"密码验证失败（连续第 {Cfg.PwdFailCount} 次）");
                    unlockErrLabel.Text = $"密码不正确（连续输错 {Cfg.PwdFailCount}/{LockoutPolicy.FailLimit} 次，"
                        + $"再错 {LockoutPolicy.FailLimit - Cfg.PwdFailCount} 次将临时锁定）";
                }
                unlockPassBox.Clear();
                unlockPassBox.Focus();
                return;
            }

            LockoutPolicy.OnSuccess(Cfg);
            Master.Wipe();
            Buffer.BlockCopy(mk.WrapKey, 0, Master.WrapKey, 0, mk.WrapKey.Length);
            mk.Wipe();
            Locked = false;
            Logger.Write("解锁", "保险库解锁成功（密码验证通过）");
            RecalculateLockTarget();
            ReloadEntries();
            Navigate("", pushHistory: false);
            HideLockOverlay();
            Toast("已解锁", true);
        }

        internal void UpdateStatusPill()
        {
            if (statusPill == null) return;
            var c = Locked ? Theme.Warn : Theme.Ok;
            statusPillDot.ForeColor = c;
            statusPillText.Text = Locked ? "保险库已锁定" : "保险库已解锁";
            statusPillText.ForeColor = Locked ? Theme.TextDim : Theme.TextDim;
            statusPill.BackColor = Theme.Card2;
            statusPillDot.Location = new Point(9, 5);
        }

        // ==================== toast 提示 ====================

        /// <summary>底部居中 toast 提示（2.4 秒后自动消失，前缀 ✅ / ⚠️ 与前端一致）。</summary>
        internal void Toast(string message, bool ok)
        {
            toastLabel.Text = (ok ? "✅ " : "⚠️ ") + message;
            toastLabel.ForeColor = ok ? Theme.Ok : Theme.Danger;
            toastLabel.BackColor = Theme.Card;
            toastLabel.Visible = true;
            toastLabel.BringToFront();
            PositionToast();
            toastTimer.Stop();
            toastTimer.Start();
        }

        private void PositionToast()
        {
            toastLabel.Left = Math.Max(0, (ClientSize.Width - toastLabel.Width) / 2);
            toastLabel.Top = Math.Max(0, ClientSize.Height - toastLabel.Height - 16);
        }

        // ==================== 视图切换与主题 ====================

        private void ShowView(bool settings)
        {
            if (Locked && settings) return; // 锁定状态下不进入设置
            viewSettings.Visible = settings;
            viewMain.Visible = !settings;
            btnSettings.Tag = settings ? "active" : null;
            btnMain.Tag = settings ? null : "active";
            ApplyActiveButton(btnMain);
            ApplyActiveButton(btnSettings);
            if (settings) LoadSettingsValues();
            toastLabel.Visible = false;
        }

        /// <summary>顶栏按钮的 active 高亮（前端 .top-btn.active）。</summary>
        private void ApplyActiveButton(Button b)
        {
            bool active = (b.Tag as string) == "active";
            b.BackColor = active ? Theme.AccentSoft : Theme.Card2;
            b.ForeColor = active ? Theme.Accent : Theme.Text;
            b.FlatAppearance.BorderColor = active ? Theme.Accent : Theme.Line;
        }

        private void ToggleTheme()
        {
            Cfg.Theme = Theme.IsDark ? "light" : "dark";
            Cfg.Save();
            Theme.Apply(Cfg.Theme);
            Theme.ApplyTo(this);
            ApplyThemeButton();
            ApplyActiveButton(btnMain);
            ApplyActiveButton(btnSettings);
            UpdateStatusPill();
            RenderTree();
            RenderBreadcrumb();
            RenderList();
            settingsTabs?.Invalidate();
            PositionToast();
        }

        /// <summary>主题按钮：浅色显示 🌙，深色显示 ☀️（前端同款）。</summary>
        private void ApplyThemeButton()
        {
            btnTheme.Text = Theme.IsDark ? "☀️" : "🌙";
            tips.SetToolTip(btnTheme, Theme.IsDark ? "切换到浅色主题" : "切换到深色主题");
        }

        // ==================== 数据与导航 ====================

        /// <summary>重新读取容器条目表。</summary>
        internal void ReloadEntries()
        {
            try
            {
                Entries = VaultFile.ListEntries(VaultPath);
            }
            catch (Exception ex)
            {
                Logger.Write("保险库", $"读取条目失败：{ex.Message}");
                MessageBox.Show(this, "读取保险库失败：" + ex.Message, "DH-BOX", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Entries = new List<VaultEntry>();
            }
        }

        /// <summary>切换当前目录并刷新界面。</summary>
        internal void Navigate(string dir, bool pushHistory = true)
        {
            Cwd = dir ?? "";
            SelectedName = "";
            RenderBreadcrumb();
            RenderTree();
            RenderList();
            UpdateStatus();
        }

        private void GoUp()
        {
            if (Cwd.Length == 0) return;
            int i = Cwd.LastIndexOf('/');
            Cwd = i < 0 ? "" : Cwd.Substring(0, i);
            Navigate(Cwd);
        }

        /// <summary>渲染左侧目录树（根行：🗄️ 我的密库（根目录））。</summary>
        private void RenderTree()
        {
            suppressTreeSelect = true;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            var root = new TreeNode("🗄️ 我的密库（根目录）") { Tag = "" };
            AddDirNodes(root, "");
            tree.Nodes.Add(root);
            root.Expand();
            SelectTreeNode(root, "");
            tree.EndUpdate();
            suppressTreeSelect = false;

            void AddDirNodes(TreeNode parent, string parentPath)
            {
                foreach (var d in DirectoriesOf(parentPath))
                {
                    var node = new TreeNode("📁 " + d.Leaf) { Tag = d.Name };
                    AddDirNodes(node, d.Name);
                    parent.Nodes.Add(node);
                }
            }
        }

        private void SelectTreeNode(TreeNode node, string path)
        {
            if ((node.Tag as string) == path) { tree.SelectedNode = node; return; }
            foreach (TreeNode child in node.Nodes) SelectTreeNode(child, path);
        }

        /// <summary>渲染面包屑（前端：DH-BOX / 段 / 段）。</summary>
        private void RenderBreadcrumb()
        {
            breadcrumb.SuspendLayout();
            breadcrumb.Controls.Clear();
            var parts = Cwd.Length == 0 ? Array.Empty<string>() : Cwd.Split('/');
            breadcrumb.Controls.Add(CrumbButton("DH-BOX", "", current: Cwd.Length == 0));
            string acc = "";
            for (int i = 0; i < parts.Length; i++)
            {
                acc = acc.Length == 0 ? parts[i] : acc + "/" + parts[i];
                breadcrumb.Controls.Add(new Label { Text = "/", AutoSize = true, Tag = "faint", Margin = new Padding(3, 8, 3, 0) });
                breadcrumb.Controls.Add(CrumbButton(parts[i], acc, current: i == parts.Length - 1));
            }
            breadcrumb.ResumeLayout();
            Theme.ApplyTo(breadcrumb);
        }

        private Button CrumbButton(string text, string path, bool current)
        {
            var b = new Button { Text = text, AutoSize = true, Margin = new Padding(0, 2, 0, 2), Tag = current ? "crumb-current" : null };
            if (current) b.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold);
            b.Click += (s, e) => Navigate(path);
            return b;
        }

        /// <summary>渲染当前目录的文件列表（目录在前 + 中文名称排序；空目录显示空状态）。</summary>
        internal void RenderList()
        {
            list.BeginUpdate();
            list.Items.Clear();
            list.Columns.Clear();
            list.Columns.Add("名称", 330);
            ColumnKeys = Cfg.Columns.ToArray();
            foreach (var key in ColumnKeys)
                list.Columns.Add(ColumnTitle(key), ColumnWidth(key));

            var items = ChildrenOf(Cwd);
            foreach (var e in items)
            {
                var item = new ListViewItem(e.Leaf) { Tag = e, Selected = e.Name == SelectedName };
                foreach (var key in ColumnKeys) item.SubItems.Add(ColumnText(e, key));
                list.Items.Add(item);
            }
            list.EndUpdate();

            bool empty = items.Count == 0;
            emptyState.Visible = empty;
            list.Visible = !empty;
            Theme.ApplyTo(list);
        }

        private static string ColumnTitle(string key) => key switch
        {
            "type" => "类型",
            "size" => "大小",
            "mtime" => "修改时间",
            "ctime" => "创建时间",
            "enc" => "加密状态",
            _ => key,
        };

        private static int ColumnWidth(string key) => key switch
        {
            "type" => 110,
            "size" => 100,
            "mtime" => 150,
            "ctime" => 150,
            "enc" => 100,
            _ => 100,
        };

        private static string ColumnText(VaultEntry e, string key) => key switch
        {
            "type" => e.IsFile ? FileTypeName(e.Leaf) : "文件夹",
            "size" => e.IsFile ? HumanSize(e.PlainLength) : "—",
            "mtime" => e.Modified == DateTime.MinValue ? "—" : e.Modified.ToString("yyyy-MM-dd HH:mm"),
            "ctime" => e.Created == DateTime.MinValue ? "—" : e.Created.ToString("yyyy-MM-dd HH:mm"),
            "enc" => e.IsFile ? "🔒 已加密" : "🔒 已加密",
            _ => "",
        };

        // ==================== 自绘列表 ====================

        /// <summary>自绘列头（faint 色文字）与行（图标 + 名称 + 已加密徽标 + 右对齐/居中列）。</summary>
        private void DrawColumnHeader(DrawListViewColumnHeaderEventArgs e)
        {
            using var back = new SolidBrush(Theme.Card);
            e.Graphics.FillRectangle(back, e.Bounds);
            using var line = new Pen(Theme.Line);
            e.Graphics.DrawLine(line, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            using var fore = new SolidBrush(Theme.TextFaint);
            var sf = new StringFormat { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Near };
            if (e.ColumnIndex > 0 && ColumnKeys.Length >= e.ColumnIndex)
            {
                string key = ColumnKeys[e.ColumnIndex - 1];
                if (key is "size" or "mtime" or "ctime") sf.Alignment = StringAlignment.Far;
                else if (key == "enc") sf.Alignment = StringAlignment.Center;
            }
            var rect = new Rectangle(e.Bounds.Left + 8, e.Bounds.Top, e.Bounds.Width - 16, e.Bounds.Height);
            e.Graphics.DrawString(e.Header.Text, e.Font, fore, rect, sf);
        }

        private void DrawSubItem(DrawListViewSubItemEventArgs e)
        {
            var item = e.Item;
            var entry = item.Tag as VaultEntry;
            if (entry == null) return;
            var g = e.Graphics;
            bool selected = item.Selected;
            using (var back = new SolidBrush(selected ? Theme.AccentSoft : Theme.Card))
                g.FillRectangle(back, e.Bounds);

            var sf = new StringFormat { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Near, FormatFlags = StringFormatFlags.NoWrap };
            var rect = new Rectangle(e.Bounds.Left + 8, e.Bounds.Top, e.Bounds.Width - 12, e.Bounds.Height);

            if (e.ColumnIndex == 0)
            {
                // 图标 + 名称 + 徽标
                using var iconFont = new Font("Segoe UI Emoji", 9.5F);
                using var iconBrush = new SolidBrush(Theme.Text);
                g.DrawString(IconOf(entry), iconFont, iconBrush, e.Bounds.Left + 6, e.Bounds.Top + (e.Bounds.Height - 18) / 2);
                using var nameBrush = new SolidBrush(selected ? Theme.Accent : Theme.Text);
                float nameX = e.Bounds.Left + 34;
                g.DrawString(entry.Leaf, list.Font, nameBrush, nameX, e.Bounds.Top + (e.Bounds.Height - list.Font.Height) / 2);
                float nameW = g.MeasureString(entry.Leaf, list.Font).Width;
                // 徽标
                string badge = entry.IsFile ? "已加密" : "已加密";
                using var badgeFont = new Font("Microsoft YaHei UI", 7.5F);
                var badgeSize = g.MeasureString(badge, badgeFont);
                float bx = nameX + nameW + 8;
                var badgeRect = new RectangleF(bx, e.Bounds.Top + (e.Bounds.Height - badgeSize.Height - 5) / 2, badgeSize.Width + 10, badgeSize.Height + 4);
                if (badgeRect.Right < e.Bounds.Right - 4)
                {
                    using var badgeBack = new SolidBrush(Theme.AccentSoft);
                    g.FillRectangle(badgeBack, badgeRect);
                    using var badgeBrush = new SolidBrush(Theme.Accent);
                    g.DrawString(badge, badgeFont, badgeBrush, badgeRect.Left + 5, badgeRect.Top + 2);
                }
            }
            else
            {
                string key = e.ColumnIndex - 1 < ColumnKeys.Length ? ColumnKeys[e.ColumnIndex - 1] : "";
                if (key is "size" or "mtime" or "ctime") sf.Alignment = StringAlignment.Far;
                else if (key == "enc") sf.Alignment = StringAlignment.Center;
                string text = e.SubItem.Text;
                Color fore = key == "enc" && entry.IsFile ? Theme.Accent : (key is "size" or "mtime" or "ctime" or "type" ? Theme.TextDim : Theme.Text);
                using var brush = new SolidBrush(fore);
                g.DrawString(text, list.Font, brush, rect, sf);
            }
        }

        /// <summary>按扩展名给出图标（前端 fileIcon 同款）。</summary>
        private static string IconOf(VaultEntry e)
        {
            if (!e.IsFile) return "📁";
            int dot = e.Leaf.LastIndexOf('.');
            string ext = dot >= 0 ? e.Leaf.Substring(dot + 1).ToLowerInvariant() : "";
            return ext switch
            {
                "pdf" => "📕",
                "txt" => "📄",
                "md" => "📝",
                "docx" => "📘",
                "xlsx" => "📗",
                "png" or "jpg" or "jpeg" => "🖼️",
                "zip" or "rar" or "7z" => "🗜️",
                "exe" => "⚙️",
                "mp4" => "🎞️",
                "mp3" => "🎵",
                _ => "🔒",
            };
        }

        /// <summary>按扩展名给出类型名（前端 ftype 同款）。</summary>
        private static string FileTypeName(string leaf)
        {
            int dot = leaf.LastIndexOf('.');
            string ext = dot >= 0 ? leaf.Substring(dot + 1).ToLowerInvariant() : "";
            return ext switch
            {
                "pdf" => "PDF 文档",
                "txt" => "文本文档",
                "md" => "Markdown",
                "docx" => "Word 文档",
                "xlsx" => "Excel 表格",
                "png" => "PNG 图片",
                "jpg" or "jpeg" => "JPEG 图片",
                "zip" => "压缩包",
                "exe" => "应用程序",
                "mp4" => "视频",
                "mp3" => "音频",
                _ => "加密文件",
            };
        }

        /// <summary>统计某目录下所有文件的总大小（递归）。</summary>
        private long DirSize(string dir)
        {
            long sum = 0;
            foreach (var e in Entries)
                if (e.IsFile && e.Name.StartsWith(dir + "/", StringComparison.OrdinalIgnoreCase))
                    sum += e.PlainLength;
            return sum;
        }

        /// <summary>当前目录的直接子项（目录在前 + 中文名称排序，前端同款）。</summary>
        private List<VaultEntry> ChildrenOf(string dir)
            => Entries
                .Where(e => e.ParentDir == dir)
                .OrderByDescending(e => !e.IsFile)
                .ThenBy(e => e.Leaf, StringComparer.Create(CultureInfo.GetCultureInfo("zh-CN"), true))
                .ToList();

        private List<VaultEntry> DirectoriesOf(string parent)
            => ChildrenOf(parent).Where(e => !e.IsFile).ToList();

        internal void SyncSelection()
        {
            SelectedName = list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is VaultEntry e ? e.Name : "";
            btnUp.Enabled = Cwd.Length > 0;
        }

        /// <summary>状态栏（前端文案）：N 个项目（含 M 个文件夹） · 占用空间 · 剪贴板。</summary>
        internal void UpdateStatus()
        {
            var items = ChildrenOf(Cwd);
            int dirs = items.Count(e => !e.IsFile);
            long size = items.Where(e => e.IsFile).Sum(e => e.PlainLength);

            statItems.Text = items.Count == 0 ? "0 个项目" : $"{items.Count} 个项目（含 {dirs} 个文件夹）";
            statSize.Text = size > 0 ? "占用空间 " + HumanSize(size) : "";
            statClip.Text = ClipItem == null ? "" : $"{(ClipMode == "cut" ? "✂️ 已剪切" : "📋 已复制")}：{ClipItem.Leaf}";
            btnUp.Enabled = Cwd.Length > 0;
        }

        /// <summary>每秒检查一次目标锁定时间戳，到点自动锁定（显示锁定覆盖层）。</summary>
        private void OnLockTick()
        {
            if (Locked) return;
            if (DateTime.UtcNow >= LockTargetUtc)
                LockVault(Cfg.LockMode == "fixed" ? "自动锁定（到达定点截止时刻）" : $"自动锁定触发（空闲超过 {Cfg.LockMinutes} 分钟）");
        }

        /// <summary>按当前配置重新计算目标锁定时间戳（解锁/保存设置后调用；"保存后立即生效"）。</summary>
        internal void RecalculateLockTarget()
        {
            var target = Cfg.ComputeLockTarget(out _) ?? DateTime.UtcNow.AddMinutes(Math.Max(1, Cfg.LockMinutes));
            LockTargetUtc = target;
        }

        /// <summary>人类可读大小（前端 fmtSize 同款：0 → “—”，KB/MB 1 位小数，GB 2 位小数）。</summary>
        internal static string HumanSize(long bytes)
        {
            if (bytes <= 0) return "—";
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024L * 1024) return (bytes / 1024.0).ToString("0.0") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / 1024.0 / 1024).ToString("0.0") + " MB";
            return (bytes / 1024.0 / 1024 / 1024).ToString("0.00") + " GB";
        }
    }

    /// <summary>WinForms 文本框占位符（.NET Framework 用 EM_SETCUEBANNER 实现）。</summary>
    internal static class PlaceholderHelper
    {
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

        public static void Set(TextBox box, string text)
        {
            // 若句柄尚未创建则延迟到创建后设置，确保占位提示完整生效
            void Apply() { try { SendMessage(box.Handle, 0x1501 /* EM_SETCUEBANNER */, new IntPtr(1), text); } catch { } }
            if (box.IsHandleCreated) Apply();
            else box.HandleCreated += (s, e) => Apply();
        }
    }
}
