using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace SecretVault
{
    /// <summary>
    /// DH-BOX 宿主程序（WebView2 架构）：
    ///   界面完全由前端网页 cipherbox-ui.html（web 目录）绘制，本进程只提供窗口壳与 C# 加密后端，
    ///   两者通过 CoreWebView2 的 WebMessage（postMessage）桥接，见 <see cref="BridgeHost"/>。
    /// 窗口采用无边框样式：标题栏由网页顶栏承担（颜色随深浅主题精确变化），
    /// 拖动 / 边缘缩放 / 最小化 / 最大化 / 关闭 都由网页顶栏和窗口按钮驱动。
    /// 加密逻辑保持不变：AES-256-CBC + HMAC-SHA256 容器、PBKDF2-HMAC-SHA256（随机盐 20 万次）派生包装密钥。
    /// </summary>
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            DpiHelper.Enable();

            // 单实例：同一保险库只允许一个进程访问（容器级互斥）
            string vault = ResolveVaultPath();
            using var mutex = new Mutex(true, VaultIds.AppName(vault), out bool createdNew);
            if (!createdNew)
            {
                MessageBox.Show("DH-BOX 已经在运行中。", "DH-BOX", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Application.Run(new HostForm());
        }

        /// <summary>定位保险库：优先配置记录的路径，其次旧版容器名，最后默认名（程序旁 DH-BOX.vault）。</summary>
        public static string ResolveVaultPath()
        {
            try
            {
                var cfg = AppConfig.Load();
                if (!string.IsNullOrEmpty(cfg.VaultPath) && File.Exists(cfg.VaultPath)) return cfg.VaultPath;
            }
            catch { }
            return AppPaths.FindExistingVault() ?? AppPaths.DefaultVaultPath;
        }
    }

    /// <summary>宿主窗体：整个客户区都是 WebView2（界面全部由 HTML/CSS/JS 呈现，不使用任何 WinForms 界面控件）。</summary>
    internal class HostForm : Form
    {
        // 手动拖动 / 缩放状态：用 15ms 轮询鼠标位置来移动窗口
        // （不依赖系统移动循环，也不依赖鼠标消息——WebView2 子窗口会拦截/抢占鼠标消息与捕获）
        private bool manualDrag;
        private bool manualResize;
        private Point opCursorStart;
        private Point dragWinStart;
        private Rectangle resizeRectStart;
        private string resizeEdge = "";
        private System.Windows.Forms.Timer? mouseOpTimer;
        private DateTime mouseOpStartUtc;

        private readonly WebView2 webView = new();
        private readonly AppConfig cfg = AppConfig.Load();
        private BridgeHost? bridge;

        /// <summary>供桥接层访问 WebView2 控件（发消息、截图）。</summary>
        public WebView2 View => webView;

        public HostForm()
        {
            // 无边框：系统标题栏完全移除（图标、文字、颜色限制都不存在了），
            // 网页顶栏即“标题栏”，深浅主题切换时颜色精确跟随。
            FormBorderStyle = FormBorderStyle.None;
            Text = "";
            ShowIcon = false;
            MinimumSize = new Size(640, 400);
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1180, 760);
            BackColor = Color.FromArgb(242, 244, 249);
            RestoreSavedBounds();   // 还原上次的窗口大小与位置

            webView.Dock = DockStyle.Fill;
            Controls.Add(webView);

            Load += async (s, e) =>
            {
                MaximizedBounds = Screen.FromControl(this).WorkingArea;  // 最大化不遮任务栏
                if (cfg.WindowMaximized) WindowState = FormWindowState.Maximized;
                await InitWebViewAsync();
            };
            LocationChanged += (s, e) => MaximizedBounds = Screen.FromControl(this).WorkingArea;
            Resize += (s, e) =>
            {
                MaximizedBounds = Screen.FromControl(this).WorkingArea;
                bridge?.PostEvent("windowState", new { maximized = WindowState == FormWindowState.Maximized });
            };
            FormClosing += (s, e) =>
            {
                SaveBounds();        // 关闭时记住窗口大小与位置
                bridge?.Shutdown();
            };
        }

        /// <summary>无边框窗口补上系统投影（CS_DROPSHADOW）；并显式声明“可最小化 + 系统菜单”，
        /// 否则点击任务栏图标不会把窗口收下去、Alt+F4 也无效。</summary>
        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.Style |= 0x00020000 | 0x00080000;   // WS_MINIMIZEBOX | WS_SYSMENU
                cp.ClassStyle |= 0x00020000;           // CS_DROPSHADOW
                return cp;
            }
        }

        /* ================= 窗口大小与位置记忆 ================= */

        private void RestoreSavedBounds()
        {
            try
            {
                if (cfg.WindowW < 640 || cfg.WindowH < 480) return;   // 无有效记录 → 默认居中
                var b = new Rectangle(cfg.WindowX, cfg.WindowY, cfg.WindowW, cfg.WindowH);
                foreach (var sc in Screen.AllScreens)
                {
                    if (!sc.WorkingArea.IntersectsWith(b)) continue;  // 窗口须仍在某块屏幕内
                    StartPosition = FormStartPosition.Manual;
                    Bounds = b;
                    return;
                }
            }
            catch { }
        }

        private void SaveBounds()
        {
            try
            {
                bool max = WindowState == FormWindowState.Maximized;
                var b = max ? RestoreBounds : Bounds;
                if (b.Width < 200 || b.Height < 150) return;
                cfg.WindowX = b.X;
                cfg.WindowY = b.Y;
                cfg.WindowW = b.Width;
                cfg.WindowH = b.Height;
                cfg.WindowMaximized = max;
                cfg.Save();
                Logger.Write("界面", $"已保存窗口状态：{b.Width}×{b.Height} @ ({b.X},{b.Y}){(max ? "（最大化）" : "")}");
            }
            catch (Exception ex)
            {
                Logger.Write("界面", "保存窗口状态失败：" + ex.Message);
            }
        }

        /* ================= 窗口控制（由网页顶栏/窗口按钮调用） ================= */

        /// <summary>开始拖动窗口（网页顶栏 / 锁定界面顶部按住并移动后调用）：轮询鼠标位置移动窗口。</summary>
        public void BeginDrag()
        {
            if (WindowState == FormWindowState.Maximized) WindowState = FormWindowState.Normal; // 最大化时拖动先还原
            opCursorStart = Cursor.Position;
            dragWinStart = Location;
            manualDrag = true;
            manualResize = false;
            mouseOpStartUtc = DateTime.UtcNow;
            EnsureMouseOpTimer();
            Logger.Write("界面", "开始拖动窗口");
        }

        /// <summary>开始边缘缩放（网页在窗口边缘按下时调用：left/right/top/bottom/topleft/topright/bottomleft/bottomright）。</summary>
        public void BeginResize(string edge)
        {
            if (edge.Length == 0 || WindowState == FormWindowState.Maximized) return;
            opCursorStart = Cursor.Position;
            resizeRectStart = Bounds;
            resizeEdge = edge;
            manualResize = true;
            manualDrag = false;
            mouseOpStartUtc = DateTime.UtcNow;
            EnsureMouseOpTimer();
            Logger.Write("界面", "开始缩放窗口：" + edge);
        }

        private void EnsureMouseOpTimer()
        {
            if (mouseOpTimer == null)
            {
                mouseOpTimer = new System.Windows.Forms.Timer { Interval = 15 };   // ≈60fps
                mouseOpTimer.Tick += (s, e) => MouseOpTick();
            }
            mouseOpTimer.Start();
        }

        /// <summary>拖动 / 缩放轮询：跟随鼠标位置移动窗口；左键松开即结束。</summary>
        private void MouseOpTick()
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DHBOX_OPERLOG")))
            {
                short k = GetAsyncKeyState(0x01);
                Logger.Write("调试", $"tick drag={manualDrag} resize={manualResize} mb=[{Control.MouseButtons}] ask=0x{(int)k:X4} cur={Cursor.Position.X},{Cursor.Position.Y} start={opCursorStart.X},{opCursorStart.Y} rect={Bounds}");
            }
            // 左键判定：两种 API 取“或”（互为补位，避免窗口移动期间的瞬时误判），并加 20 秒超时兜底
            bool leftDown = (Control.MouseButtons & MouseButtons.Left) != 0
                            || (GetAsyncKeyState(0x01) & 0x8000) != 0;
            bool opTimeout = (DateTime.UtcNow - mouseOpStartUtc).TotalSeconds > 20;
            if (!leftDown || opTimeout)
            {
                mouseOpTimer?.Stop();
                manualDrag = false;
                manualResize = false;
                return;
            }

            var cur = Cursor.Position;
            if (manualDrag)
            {
                Location = new Point(dragWinStart.X + (cur.X - opCursorStart.X),
                                     dragWinStart.Y + (cur.Y - opCursorStart.Y));
            }
            else if (manualResize)
            {
                int dx = cur.X - opCursorStart.X, dy = cur.Y - opCursorStart.Y;
                var r = resizeRectStart;
                int x = r.X, y = r.Y, w = r.Width, h = r.Height;
                if (resizeEdge.Contains("left")) { x = r.X + dx; w = r.Width - dx; }
                else if (resizeEdge.Contains("right")) { w = r.Width + dx; }
                if (resizeEdge.Contains("top")) { y = r.Y + dy; h = r.Height - dy; }
                else if (resizeEdge.Contains("bottom")) { h = r.Height + dy; }
                // 最小尺寸约束（注意单位：Bounds/SetBounds 是物理像素，MinimumSize 是逻辑值）
                double scale = DeviceDpi / 96.0;
                int minW = (int)Math.Ceiling(MinimumSize.Width * scale) + 2;
                int minH = (int)Math.Ceiling(MinimumSize.Height * scale) + 2;
                if (w < minW)
                {
                    if (resizeEdge.Contains("left")) x = r.Right - minW;
                    w = minW;
                }
                if (h < minH)
                {
                    if (resizeEdge.Contains("top")) y = r.Bottom - minH;
                    h = minH;
                }
                SetBounds(x, y, w, h);
            }
            else
            {
                mouseOpTimer?.Stop();
            }
        }

        public void WindowAction(string action)
        {
            switch (action)
            {
                case "minimize":
                    WindowState = FormWindowState.Minimized;
                    break;
                case "maximizeToggle":
                    WindowState = WindowState == FormWindowState.Maximized
                        ? FormWindowState.Normal
                        : FormWindowState.Maximized;
                    break;
                case "close":
                    Close();
                    break;
            }
        }

        /// <summary>
        /// 无边框模式下标题栏由网页绘制（颜色随主题精确变化），此处保留 DWM 调用仅影响系统窗口边框/投影。
        /// </summary>
        public void ApplyWindowTheme(bool dark)
        {
            try
            {
                int v = dark ? 1 : 0;
                DwmSetWindowAttribute(Handle, 20, ref v, sizeof(int)); // DWMWA_USE_IMMERSIVE_DARK_MODE
                DwmSetWindowAttribute(Handle, 19, ref v, sizeof(int));  // 旧版 Win10 的属性号
            }
            catch { }
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        /// <summary>读取编译进 exe 的界面 HTML（嵌入资源 DHBOX_UI_HTML）；不存在返回 null。</summary>
        private static byte[]? LoadEmbeddedHtml()
        {
            try
            {
                using var s = System.Reflection.Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream("DHBOX_UI_HTML");
                if (s == null) return null;
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                return ms.ToArray();
            }
            catch { return null; }
        }

        /* ================= WebView2 初始化 ================= */

        private async Task InitWebViewAsync()
        {
            string webDir = Path.Combine(AppPaths.ExeDir, "web");
            string html = Path.Combine(webDir, "cipherbox-ui.html");
            try
            {
                // 界面来源：优先使用程序旁的 web\cipherbox-ui.html（便于自定义界面）；
                // 没有外部文件时使用编译进 exe 的内嵌界面（单文件分发，无需 web 目录）
                byte[]? embeddedHtml = null;
                if (!File.Exists(html))
                {
                    embeddedHtml = LoadEmbeddedHtml();
                    if (embeddedHtml == null)
                    {
                        MessageBox.Show(this,
                            "界面资源缺失：exe 内嵌界面不可用，且未找到外部文件：\n" + html,
                            "DH-BOX", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Close();
                        return;
                    }
                }

                // 绿色便携：WebView2 用户数据目录放在程序旁边
                string userData = Path.Combine(AppPaths.ExeDir, "WebView2Data");
                var env = await CoreWebView2Environment.CreateAsync(null, userData);
                await webView.EnsureCoreWebView2Async(env);

                var core = webView.CoreWebView2;
                core.Settings.AreDefaultContextMenusEnabled = false;   // 右键菜单由页面自己实现
                core.Settings.IsStatusBarEnabled = false;
                core.Settings.IsZoomControlEnabled = false;
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.IsPasswordAutosaveEnabled = false;
                core.Settings.IsGeneralAutofillEnabled = false;

                bridge = new BridgeHost(this);
                core.WebMessageReceived += bridge.OnWebMessage;

                // 安全：只允许停留在本地界面站点；拦截外部导航、新窗口与外部文件拖放
                webView.AllowExternalDrop = false;
                core.NewWindowRequested += (s, e) => e.Handled = true;
                core.NavigationStarting += (s, e) =>
                {
                    if (!e.Uri.StartsWith("https://dhbox.local/", StringComparison.OrdinalIgnoreCase))
                    {
                        e.Cancel = true;
                        Logger.Write("安全", "已拦截外部导航：" +
                            (e.Uri.Length > 300 ? e.Uri.Substring(0, 300) : e.Uri));
                    }
                };
                core.ProcessFailed += (s, e) => Logger.Write("界面", "WebView2 进程异常：" + e.ProcessFailedKind);

                if (embeddedHtml == null)
                {
                    // 外部文件模式：只把 web 子目录映射为虚拟站点（保险库文件不在其中，网页无法读取本机其他文件）
                    core.SetVirtualHostNameToFolderMapping("dhbox.local", webDir, CoreWebView2HostResourceAccessKind.Allow);
                    Logger.Write("界面", "使用外部界面文件：" + html);
                }
                else
                {
                    // 单文件模式：界面直接由 exe 内嵌资源提供（磁盘上不落地任何 HTML）
                    var assets = embeddedHtml;
                    core.AddWebResourceRequestedFilter("https://dhbox.local/*", CoreWebView2WebResourceContext.All);
                    core.WebResourceRequested += (s, e) =>
                    {
                        try
                        {
                            string path = new Uri(e.Request.Uri).AbsolutePath;
                            if (path == "/" || path.Equals("/cipherbox-ui.html", StringComparison.OrdinalIgnoreCase))
                            {
                                e.Response = core.Environment.CreateWebResourceResponse(
                                    new MemoryStream(assets), 200, "OK", "Content-Type: text/html; charset=utf-8");
                            }
                            else
                            {
                                e.Response = core.Environment.CreateWebResourceResponse(
                                    new MemoryStream(new byte[0]), 404, "Not Found", "Content-Type: text/plain");
                            }
                        }
                        catch { }
                    };
                    Logger.Write("界面", "使用 exe 内嵌界面（单文件模式，未在磁盘落地 HTML）");
                }

                // 调试截图模式（可选）：设置环境变量 DHBOX_SHOT=输出.png，
                // 可选 DHBOX_SHOT_MODE=main|setup|lock|settings、DHBOX_SHOT_THEME=light|dark，
                // 页面渲染完成后自动截图并退出（仅用于界面核对，不影响正常使用）。
                string shot = Environment.GetEnvironmentVariable("DHBOX_SHOT") ?? "";
                if (shot.Length > 0)
                {
                    string mode = Environment.GetEnvironmentVariable("DHBOX_SHOT_MODE") ?? "";
                    string theme = Environment.GetEnvironmentVariable("DHBOX_SHOT_THEME") ?? "";
                    var q = new System.Collections.Generic.List<string>();
                    if (mode.Length > 0) q.Add("mode=" + Uri.EscapeDataString(mode));
                    if (theme.Length > 0) q.Add("theme=" + Uri.EscapeDataString(theme));
                    string url = "https://dhbox.local/cipherbox-ui.html" + (q.Count > 0 ? "?" + string.Join("&", q) : "");
                    string shotScriptFile = Environment.GetEnvironmentVariable("DHBOX_SHOT_SCRIPT_FILE") ?? "";
                    core.NavigationCompleted += async (s2, e2) =>
                    {
                        await Task.Delay(1200);
                        if (shotScriptFile.Length > 0 && File.Exists(shotScriptFile))
                        {
                            try
                            {
                                await core.ExecuteScriptAsync(File.ReadAllText(shotScriptFile, System.Text.Encoding.UTF8));
                            }
                            catch (Exception ex) { Logger.Write("界面", "调试脚本执行失败：" + ex.Message); }
                        }
                        int shotDelay = int.TryParse(Environment.GetEnvironmentVariable("DHBOX_SHOT_DELAY"), out var sd) ? sd : 4000;
                        await Task.Delay(shotDelay);
                        try
                        {
                            using var ms = new MemoryStream();
                            await core.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, ms);
                            File.WriteAllBytes(shot, ms.ToArray());
                            Logger.Write("界面", "已保存界面截图：" + shot);
                        }
                        catch (Exception ex) { Logger.Write("界面", "界面截图失败：" + ex.Message); }
                        Close();
                    };
                    core.Navigate(url);
                }
                else
                {
                    core.Navigate("https://dhbox.local/cipherbox-ui.html");
                }
                Logger.Write("界面", $"WebView2 初始化完成（浏览器内核 {env.BrowserVersionString}）");
            }
            catch (Exception ex)
            {
                Logger.Write("界面", "WebView2 初始化失败：" + ex.Message);
                MessageBox.Show(this,
                    "WebView2 初始化失败：\n" + ex.Message +
                    "\n\n请确认已安装 Microsoft Edge WebView2 Runtime（Win10/Win11 通常自带；" +
                    "缺失时可从微软官网下载 Evergreen 安装包）。",
                    "DH-BOX", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close();
            }
        }
    }

    /// <summary>进程级 DPI 感知：优先 PerMonitorV2，回退系统级感知（WebView2 内容随 DPI 自动缩放）。</summary>
    internal static class DpiHelper
    {
        [DllImport("user32.dll")] private static extern bool SetProcessDpiAwarenessContext(IntPtr ctx);
        [DllImport("user32.dll")] private static extern bool SetProcessDPIAware();

        public static void Enable()
        {
            try { if (!SetProcessDpiAwarenessContext(new IntPtr(-4))) SetProcessDPIAware(); }
            catch { try { SetProcessDPIAware(); } catch { } }
        }
    }
}
