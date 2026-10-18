using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace SecretVault
{
    /// <summary>
    /// 设置视图 —— 完全按照 cipherbox-ui.html 前端实现：
    ///   左侧导航：← 返回主界面 + 🔑 修改密码 / 📜 查看日志 / ⏱️ 自动锁定（点击高亮，右侧内容切换）；
    ///   修改密码：旧密码 / 新密码（4 格强度条，级别与标签文案同前端）/ 确认新密码 + 错误提示；
    ///   查看日志：刷新、清空日志、条数统计、日志文件路径、带级别着色的日志视图（info/warn/error/ok）；
    ///   自动锁定：两个可点击的模式卡片（⏲️ 自定义时长模式、📍 定点临时解锁模式）+ 步进器（− 1~1440 ＋）
    ///             + 截止时刻选择 + 当前策略说明（deadlineNote）+ 保存设置（保存后立即生效）。
    /// </summary>
    public partial class VaultForm
    {
        // 导航与页面
        private Control? settingsTabs;                       // 设置内容容器（主题切换时重绘）
        private readonly Label[] navItems = new Label[3];
        private readonly Panel[] navPages = new Panel[3];
        private int navIndex;

        // 修改密码
        private TextBox pwOldBox = null!, pwNewBox = null!, pwConfirmBox = null!;
        private Panel[] pwBars = Array.Empty<Panel>();
        private Label pwStrengthLabel = null!, pwErrLabel = null!;

        // 查看日志
        private RichTextBox logBox = null!;
        private Label logCountLabel = null!, logPathLabel = null!;

        // 自动锁定
        private Panel modeDuration = null!, modeUntil = null!, durationBody = null!, untilBody = null!;
        private Label modeDurationDot = null!, modeUntilDot = null!;
        private NumericUpDown numMinutes = null!;
        private DateTimePicker dtpDeadline = null!;
        private Label deadlineNote = null!;
        private readonly Timer deadlineTimer = new() { Interval = 1000 };

        /// <summary>设置视图（左侧导航 + 三个页面）。</summary>
        private Panel BuildSettingsView()
        {
            var root = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 10, 16, 14) };

            // 左侧导航
            var nav = new Panel { Dock = DockStyle.Left, Width = 196, Tag = "card", Padding = new Padding(10, 12, 10, 10) };
            var back = new LinkLabel
            {
                Text = "← 返回主界面",
                Dock = DockStyle.Top,
                Height = 32,
                Tag = "accent",
                Padding = new Padding(6, 6, 0, 0),
            };
            back.Click += (s, e) => ShowView(settings: false);

            var items = new (string Text, Action Act)[]
            {
                ("🔑 修改密码", () => SelectNav(0)),
                ("📜 查看日志", () => SelectNav(1)),
                ("⏱️ 自动锁定", () => SelectNav(2)),
            };
            var navList = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 8, 0, 0),
            };
            for (int i = 0; i < items.Length; i++)
            {
                int idx = i;
                var item = new Label
                {
                    Text = items[idx].Text,
                    AutoSize = false,
                    Size = new Size(168, 34),
                    TextAlign = ContentAlignment.MiddleLeft,
                    Padding = new Padding(10, 0, 0, 0),
                    Cursor = Cursors.Hand,
                };
                item.Click += (s, e) => items[idx].Act();
                navItems[idx] = item;
                navList.Controls.Add(item);
            }
            nav.Controls.Add(navList);
            nav.Controls.Add(back);

            // 右侧内容
            var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 0, 0, 0) };
            navPages[0] = BuildPasswordPage();
            navPages[1] = BuildLogPage();
            navPages[2] = BuildLockPage();
            foreach (var p in navPages) { p.Dock = DockStyle.Fill; p.Visible = false; body.Controls.Add(p); }
            navPages[0].Visible = true;
            settingsTabs = body;

            root.Controls.Add(body);
            root.Controls.Add(nav);

            // 策略说明每秒刷新（定点模式显示剩余时间，前端同款行为）
            deadlineTimer.Tick += (s, e) => UpdateDeadlineNote();
            deadlineTimer.Start();

            return root;
        }

        /// <summary>切换设置页（前端 .nav-item.active 高亮 + 内容切换）。</summary>
        private void SelectNav(int index)
        {
            navIndex = index;
            for (int i = 0; i < navPages.Length; i++) navPages[i].Visible = i == index;
            ApplyNavStyles();
            if (index == 1) LoadLog();
            if (index == 2) LoadLockUI();
        }

        private void ApplyNavStyles()
        {
            for (int i = 0; i < navItems.Length; i++)
            {
                bool active = i == navIndex;
                navItems[i].BackColor = active ? Theme.AccentSoft : Theme.Card;
                navItems[i].ForeColor = active ? Theme.Accent : Theme.Text;
            }
        }

        /// <summary>页面通用结构：标题 + 描述 + 卡片内容。</summary>
        private static (Panel page, TableLayoutPanel card) PageFrame(string title, string desc)
        {
            var page = new Panel();
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1 };
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var titleLabel = new Label
            {
                Text = title,
                Font = new Font("Microsoft YaHei UI", 13F, FontStyle.Bold),
                AutoSize = true,
                Margin = new Padding(2, 2, 0, 0),
            };
            var descLabel = new Label { Text = desc, AutoSize = true, Tag = "dim", Margin = new Padding(2, 0, 0, 0) };
            grid.Controls.Add(titleLabel, 0, 0);
            grid.Controls.Add(descLabel, 0, 1);

            var holder = new Panel { Dock = DockStyle.Fill, Tag = "card", Padding = new Padding(18, 14, 18, 14) };
            var card = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1 };
            holder.Controls.Add(card);
            grid.Controls.Add(holder, 0, 2);
            page.Controls.Add(grid);
            return (page, card);
        }

        private static int CardRow(TableLayoutPanel card)
        {
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            return card.RowCount - 1;
        }

        // ---------- 修改密码 ----------
        private Panel BuildPasswordPage()
        {
            var (page, card) = PageFrame("修改密码", "修改保险库主密码。修改后请妥善保管新密码，遗忘将无法恢复数据。");

            var oldLabel = new Label { Text = "旧密码", AutoSize = true, Tag = "dim", Margin = new Padding(0, 0, 0, 4) };
            pwOldBox = new TextBox { Width = 360, UseSystemPasswordChar = true, Margin = new Padding(0, 0, 0, 14) };
            PlaceholderHelper.Set(pwOldBox, "请输入当前密码");

            var newLabel = new Label { Text = "新密码", AutoSize = true, Tag = "dim", Margin = new Padding(0, 0, 0, 4) };
            pwNewBox = new TextBox { Width = 360, UseSystemPasswordChar = true, Margin = new Padding(0, 0, 0, 6) };
            PlaceholderHelper.Set(pwNewBox, "6 位以上，建议包含大小写字母与数字");
            pwNewBox.TextChanged += (s, e) => RefreshStrength();

            var bars = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 4) };
            pwBars = new Panel[4];
            for (int i = 0; i < 4; i++)
            {
                pwBars[i] = new Panel { Size = new Size(80, 4), Margin = new Padding(0, 0, 5, 0), BackColor = Theme.Line };
                bars.Controls.Add(pwBars[i]);
            }
            pwStrengthLabel = new Label { Text = "请输入新密码", AutoSize = true, Tag = "faint", Margin = new Padding(0, 0, 0, 14), Font = new Font("Microsoft YaHei UI", 8.5F) };
            var strengthBlock = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Margin = new Padding(0, 0, 0, 14) };
            strengthBlock.Controls.Add(bars, 0, 0);
            strengthBlock.Controls.Add(pwStrengthLabel, 0, 1);

            var confirmLabel = new Label { Text = "确认新密码", AutoSize = true, Tag = "dim", Margin = new Padding(0, 0, 0, 4) };
            pwConfirmBox = new TextBox { Width = 360, UseSystemPasswordChar = true, Margin = new Padding(0, 0, 0, 4) };
            PlaceholderHelper.Set(pwConfirmBox, "再次输入新密码");
            pwErrLabel = new Label { Text = "", AutoSize = true, ForeColor = Theme.Danger, Margin = new Padding(0, 0, 0, 10), MaximumSize = new Size(420, 0) };

            var btn = new Button { Text = "修改密码", AutoSize = true, Tag = "primary", Margin = new Padding(0, 4, 0, 0) };
            btn.Click += (s, e) => OnChangePassword();

            card.Controls.Add(oldLabel, 0, CardRow(card));
            card.Controls.Add(pwOldBox, 0, CardRow(card));
            card.Controls.Add(newLabel, 0, CardRow(card));
            card.Controls.Add(pwNewBox, 0, CardRow(card));
            card.Controls.Add(strengthBlock, 0, CardRow(card));
            card.Controls.Add(confirmLabel, 0, CardRow(card));
            card.Controls.Add(pwConfirmBox, 0, CardRow(card));
            card.Controls.Add(pwErrLabel, 0, CardRow(card));
            card.Controls.Add(btn, 0, CardRow(card));
            return page;
        }

        /// <summary>密码强度（前端 pwStrengthLevel）：长度≥6、含大小写、含数字与符号、长度≥10。</summary>
        private static int StrengthLevel(string pw)
        {
            int score = 0;
            if (pw.Length >= 6) score++;
            if (pw.Any(char.IsLower) && pw.Any(char.IsUpper)) score++;
            if (pw.Any(char.IsDigit) && pw.Any(c => !char.IsLetterOrDigit(c))) score++;
            if (pw.Length >= 10) score++;
            return Math.Min(score, 4);
        }

        private void RefreshStrength()
        {
            string pw = pwNewBox.Text;
            int level = pw.Length == 0 ? 0 : StrengthLevel(pw);
            // 前端：level1 → 第 1 格 danger；level2 → 前 2 格 warn；level3 → 前 3 格 #6ea2ff；level4 → 全部 ok
            Color fill = level switch
            {
                1 => Theme.Danger,
                2 => Theme.Warn,
                3 => Color.FromArgb(110, 162, 255),
                _ => Theme.Ok,
            };
            for (int i = 0; i < 4; i++)
                pwBars[i].BackColor = i < level ? fill : Theme.Line;
            string[] labels = { "请输入新密码", "弱 — 建议加强", "一般", "良好", "强" };
            pwStrengthLabel.Text = pw.Length == 0 ? "请输入新密码" : labels[level];
            pwStrengthLabel.ForeColor = Theme.TextFaint;
        }

        private void OnChangePassword()
        {
            pwErrLabel.Text = "";
            string oldPwd = pwOldBox.Text, newPwd = pwNewBox.Text, confirm = pwConfirmBox.Text;
            if (VaultFile.TryUnlock(VaultPath, oldPwd, out _) == null) { pwErrLabel.Text = "旧密码不正确"; return; }
            if (newPwd.Length < 6) { pwErrLabel.Text = "新密码至少 6 位"; return; }
            if (newPwd != confirm) { pwErrLabel.Text = "两次输入的新密码不一致"; return; }
            if (newPwd == oldPwd) { pwErrLabel.Text = "新密码不能与旧密码相同"; return; }
            try
            {
                if (!VaultFile.ChangePassword(VaultPath, oldPwd, newPwd, out string err))
                {
                    Logger.Write("修改密码", $"失败：{err}");
                    pwErrLabel.Text = err;
                    return;
                }
                Logger.Write("修改密码", "主密码修改成功");
                pwOldBox.Clear(); pwNewBox.Clear(); pwConfirmBox.Clear();
                RefreshStrength();
                Toast("密码修改成功", true);
            }
            catch (Exception ex) { pwErrLabel.Text = ex.Message; }
        }

        // ---------- 查看日志 ----------
        private Panel BuildLogPage()
        {
            var (page, card) = PageFrame("查看日志", "运行日志仅保存在本机，用于问题排查与安全审计。");
            card.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            card.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            card.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var toolRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Margin = new Padding(0) };
            toolRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            toolRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            toolRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            var refresh = new Button { Text = "🔄 刷新", AutoSize = true, Margin = new Padding(0, 4, 8, 4) };
            var clear = new Button { Text = "🗑️ 清空日志", AutoSize = true, Margin = new Padding(0, 4, 8, 4) };
            clear.ForeColor = Theme.Danger;
            refresh.Click += (s, e) =>
            {
                Logger.Write("日志视图", "用户刷新了日志视图");
                LoadLog();
                Toast("日志已刷新", true);
            };
            clear.Click += (s, e) => OnClearLog();
            logCountLabel = new Label { AutoSize = true, Tag = "faint", Anchor = AnchorStyles.Right, Margin = new Padding(0, 10, 2, 0) };
            toolRow.Controls.Add(refresh, 0, 0);
            toolRow.Controls.Add(clear, 1, 0);
            toolRow.Controls.Add(logCountLabel, 2, 0);

            logPathLabel = new Label { Text = "日志文件路径：" + Logger.LogFilePath, AutoSize = true, Tag = "faint", Margin = new Padding(2, 4, 0, 6), Font = new Font("Microsoft YaHei UI", 8.5F) };

            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = Theme.LogBg,
                ForeColor = Theme.Text,
                Font = new Font("Consolas", 9F),
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                DetectUrls = false,
            };

            card.Controls.Add(toolRow, 0, 0);
            card.Controls.Add(logPathLabel, 0, 1);
            card.Controls.Add(logBox, 0, 2);
            return page;
        }

        /// <summary>把容器日志渲染为带级别着色的视图（前端 log-view：时间灰、[级别] 着色）。</summary>
        private void LoadLog()
        {
            var lines = Logger.ReadTail(500)
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            logBox.Clear();
            int count = 0;
            foreach (var raw in lines)
            {
                if (raw.StartsWith("（", StringComparison.Ordinal)) continue; // “暂无日志”等占位行
                string time = "", cat = "", msg = raw;
                if (raw.StartsWith("[") && raw.Length > 21)
                {
                    int tEnd = raw.IndexOf(']');
                    if (tEnd > 0)
                    {
                        time = raw.Substring(1, tEnd - 1);
                        msg = raw.Substring(tEnd + 1).TrimStart();
                        if (msg.StartsWith("["))
                        {
                            int cEnd = msg.IndexOf(']');
                            if (cEnd > 0) { cat = msg.Substring(1, cEnd - 1); msg = msg.Substring(cEnd + 1).TrimStart(); }
                        }
                    }
                }
                string lv = InferLogLevel(cat, msg);
                AppendLogLine(time, lv, msg);
                count++;
            }
            if (count == 0)
            {
                logBox.SelectionColor = Theme.TextFaint;
                logBox.AppendText("\n暂无日志记录");
            }
            logCountLabel.Text = $"{count} 条";
            logBox.SelectionStart = logBox.TextLength;
            logBox.ScrollToCaret();
        }

        /// <summary>由类别与消息推断日志级别（info / warn / error / ok）。</summary>
        private static string InferLogLevel(string cat, string msg)
        {
            string all = cat + " " + msg;
            if (all.Contains("失败") || all.Contains("错误") || all.Contains("异常") || all.Contains("拒绝")
                || all.Contains("损坏") || all.Contains("不正确") || all.Contains("未通过"))
                return "error";
            if (all.Contains("警告") || all.Contains("跳过") || all.Contains("等待"))
                return "warn";
            if (all.Contains("成功") || all.Contains("完成") || all.Contains("通过") || all.Contains("已保存")
                || all.Contains("已恢复") || all.Contains("已刷新") || all.Contains("已清空"))
                return "ok";
            return "info";
        }

        private void AppendLogLine(string time, string level, string message)
        {
            Color lvColor = level switch
            {
                "warn" => Theme.Warn,
                "error" => Theme.Danger,
                "ok" => Theme.Ok,
                _ => Theme.Accent,
            };
            logBox.SelectionColor = Theme.TextFaint;
            logBox.AppendText($"[{time}] ");
            logBox.SelectionColor = lvColor;
            using (var bold = new Font(logBox.Font, FontStyle.Bold))
                logBox.SelectionFont = bold;
            logBox.AppendText($"[{level.ToUpperInvariant().PadRight(5)}] ");
            logBox.SelectionFont = new Font(logBox.Font, FontStyle.Regular);
            logBox.SelectionColor = Theme.Text;
            logBox.AppendText(message + Environment.NewLine);
        }

        private void OnClearLog()
        {
            if (ConfirmDialog.Show(this, "🗑️ 清空日志", "确定要清空全部日志吗？此操作不可恢复。", "清空", danger: true) != DialogResult.OK) return;
            Logger.Clear();
            LoadLog();
            Toast("日志已清空", true);
        }

        // ---------- 自动锁定 ----------
        private Panel BuildLockPage()
        {
            var (page, card) = PageFrame("自动锁定", "无人操作一段时间后自动锁定保险库；或设定一个临时解锁截止时刻，到点自动锁定。");

            // 模式卡片 1：自定义时长模式
            modeDuration = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 14, 10), Margin = new Padding(0, 0, 0, 12), Tag = "card" };
            modeDurationDot = new Label { Text = "●", AutoSize = true, Location = new Point(4, 6), Font = new Font("Microsoft YaHei UI", 9F) };
            var dTitle = new Label { Text = "⏲️ 自定义时长模式", AutoSize = true, Location = new Point(22, 4), Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold) };
            var dDesc = new Label { Text = "空闲超过设定时长后自动锁定保险库，默认 20 分钟。", AutoSize = true, Tag = "dim", Location = new Point(22, 28) };
            durationBody = new Panel { Location = new Point(22, 52), AutoSize = true };
            var minus = new Button { Text = "−", Size = new Size(30, 26), Location = new Point(0, 0) };
            numMinutes = new NumericUpDown { Minimum = 1, Maximum = 1440, Value = 20, Width = 76, Location = new Point(34, 0) };
            numMinutes.Controls[0].Visible = false; // 隐藏自带微调按钮（前端为 − / ＋ 步进器）
            var plus = new Button { Text = "＋", Size = new Size(30, 26), Location = new Point(114, 0) };
            var unit = new Label { Text = "分钟（1 ~ 1440 的整数）", AutoSize = true, Tag = "faint", Location = new Point(156, 5) };
            minus.Click += (s, e) => numMinutes.Value = Math.Max(numMinutes.Minimum, numMinutes.Value - 1);
            plus.Click += (s, e) => numMinutes.Value = Math.Min(numMinutes.Maximum, numMinutes.Value + 1);
            durationBody.Controls.AddRange(new Control[] { minus, numMinutes, plus, unit });
            modeDuration.Controls.AddRange(new Control[] { modeDurationDot, dTitle, dDesc, durationBody });

            // 模式卡片 2：定点临时解锁模式
            modeUntil = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 14, 10), Margin = new Padding(0, 0, 0, 12), Tag = "card" };
            modeUntilDot = new Label { Text = "●", AutoSize = true, Location = new Point(4, 6), Font = new Font("Microsoft YaHei UI", 9F) };
            var uTitle = new Label { Text = "📍 定点临时解锁模式", AutoSize = true, Location = new Point(22, 4), Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold) };
            var uDesc = new Label { Text = "临时解锁到未来某一时刻，期间无需重复输入密码，到点自动锁定。", AutoSize = true, Tag = "dim", Location = new Point(22, 28) };
            untilBody = new Panel { Location = new Point(22, 52), AutoSize = true };
            dtpDeadline = new DateTimePicker
            {
                Format = DateTimePickerFormat.Custom,
                CustomFormat = "yyyy-MM-dd HH:mm",
                ShowUpDown = true,
                Width = 170,
                Location = new Point(0, 0),
                MinDate = DateTime.Now.AddMinutes(1),
            };
            untilBody.Controls.Add(dtpDeadline);
            modeUntil.Controls.AddRange(new Control[] { modeUntilDot, uTitle, uDesc, untilBody });

            // 点击卡片（含子控件）即选中该模式
            SubscribeClick(modeDuration, () => SelectMode("duration"));
            SubscribeClick(modeUntil, () => SelectMode("until"));

            deadlineNote = new Label { Text = "", AutoSize = true, Tag = "dim", Margin = new Padding(2, 0, 0, 10), MaximumSize = new Size(560, 0) };

            var saveRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 0) };
            var save = new Button { Text = "💾 保存设置", AutoSize = true, Tag = "primary", Margin = new Padding(0, 0, 10, 0) };
            save.Click += (s, e) => OnSaveLock();
            var saveHint = new Label { Text = "保存后立即生效", AutoSize = true, Tag = "faint", Margin = new Padding(0, 7, 0, 0) };
            saveRow.Controls.Add(save);
            saveRow.Controls.Add(saveHint);

            card.Controls.Add(modeDuration, 0, CardRow(card));
            card.Controls.Add(modeUntil, 0, CardRow(card));
            card.Controls.Add(deadlineNote, 0, CardRow(card));
            card.Controls.Add(saveRow, 0, CardRow(card));
            return page;
        }

        /// <summary>递归绑定点击事件（点击卡片任意位置即选中模式，前端 .mode-row 同款）。</summary>
        private static void SubscribeClick(Control control, Action action)
        {
            control.Click += (s, e) => action();
            foreach (Control child in control.Controls) SubscribeClick(child, action);
        }

        private void SelectMode(string mode)
        {
            Cfg.LockMode = mode == "until" ? "fixed" : "duration";
            ApplyModeStyle();
            UpdateDeadlineNote();
        }

        private void ApplyModeStyle()
        {
            bool duration = Cfg.LockMode != "fixed";
            modeDuration.BackColor = duration ? Theme.AccentSoft : Theme.Card;
            modeUntil.BackColor = duration ? Theme.Card : Theme.AccentSoft;
            modeDurationDot.ForeColor = duration ? Theme.Accent : Theme.Line;
            modeUntilDot.ForeColor = duration ? Theme.Line : Theme.Accent;
            durationBody.Visible = duration;
            untilBody.Visible = !duration;
            modeDuration.Height = duration ? 92 : 52;
            modeUntil.Height = duration ? 52 : 92;
        }

        /// <summary>载入自动锁定配置（前端 renderLockUI）。</summary>
        private void LoadLockUI()
        {
            bool duration = Cfg.LockMode != "fixed";
            numMinutes.Value = Math.Max(numMinutes.Minimum, Math.Min(Cfg.LockMinutes, numMinutes.Maximum));
            DateTime baseTime = DateTime.Now.AddHours(2);
            if (!duration && !string.IsNullOrEmpty(Cfg.LockDeadlineUtc)
                && DateTime.TryParse(Cfg.LockDeadlineUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d))
            {
                baseTime = d.ToLocalTime();
            }
            try { dtpDeadline.Value = baseTime; } catch { dtpDeadline.Value = DateTime.Now.AddHours(2); }
            ApplyModeStyle();
            UpdateDeadlineNote();
        }

        /// <summary>当前策略说明（前端 deadlineNote：含剩余时间，每秒刷新）。</summary>
        private void UpdateDeadlineNote()
        {
            if (deadlineNote == null || !deadlineNote.IsHandleCreated) return;
            if (Cfg.LockMode != "fixed")
            {
                deadlineNote.Text = $"当前策略：自定义时长模式 —— 空闲超过 {Cfg.LockMinutes} 分钟后自动锁定。";
                return;
            }
            if (!string.IsNullOrEmpty(Cfg.LockDeadlineUtc)
                && DateTime.TryParse(Cfg.LockDeadlineUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d))
            {
                var local = d.ToLocalTime();
                var diff = local - DateTime.Now;
                string left = diff > TimeSpan.Zero
                    ? $"{(int)diff.TotalHours} 小时 {diff.Minutes} 分钟"
                    : "已到期";
                deadlineNote.Text = $"当前策略：定点临时解锁模式 —— 临时解锁截止时刻为 {FmtDeadline(local)}（剩余 {left}），到点自动锁定。";
            }
            else
            {
                deadlineNote.Text = "当前策略：定点临时解锁模式 —— 请选择截止时刻后点击「保存设置」。";
            }
        }

        private static string FmtDeadline(DateTime d)
            => $"{d.Year} 年 {d.Month} 月 {d.Day} 日 {d.ToString("HH:mm")}";

        private void OnSaveLock()
        {
            if (Cfg.LockMode == "fixed")
            {
                var d = dtpDeadline.Value;
                if (d <= DateTime.Now)
                {
                    Toast("请选择一个未来的截止时刻", false);
                    return;
                }
                Cfg.LockDeadlineUtc = d.ToUniversalTime().ToString("o");
                Logger.Write("自动锁定", $"自动锁定设置已更改：定点临时解锁至 {FmtDeadline(d)}");
                Toast($"已保存：临时解锁至 {FmtDeadline(d)}", true);
            }
            else
            {
                int v = (int)Math.Min(1440, Math.Max(1, numMinutes.Value));
                Cfg.LockMinutes = v;
                Logger.Write("自动锁定", $"自动锁定设置已更改：自定义时长模式，{v} 分钟");
                Toast($"已保存：空闲 {v} 分钟自动锁定", true);
            }
            Cfg.Save();
            RecalculateLockTarget();   // “保存后立即生效”
            UpdateDeadlineNote();
        }

        /// <summary>进入设置视图时载入最新值。</summary>
        private void LoadSettingsValues()
        {
            SelectNav(0);
            LoadLog();
            LoadLockUI();
            RefreshStrength();
            pwErrLabel.Text = "";
        }
    }
}
