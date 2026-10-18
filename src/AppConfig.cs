using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace SecretVault
{
    /// <summary>
    /// 程序配置（DH-BOX.config，与 exe 同目录，绿色便携；不设隐藏属性以保证任何环境可写）。
    /// 只保存非机密运行参数，绝不保存任何明文密码/密钥。
    /// </summary>
    public class AppConfig
    {
        /// <summary>保险库容器文件路径（固定绑定 exe 同目录，首次运行自动确定）。</summary>
        public string VaultPath { get; set; } = "";

        /// <summary>自动锁定模式："duration" = 自定义时长；"fixed" = 定点临时解锁。</summary>
        public string LockMode { get; set; } = "duration";

        /// <summary>自定义时长（分钟），默认 20。</summary>
        public int LockMinutes { get; set; } = 20;

        /// <summary>定点临时解锁截止时间（UTC ISO-8601 字符串，可为空）。</summary>
        public string LockDeadlineUtc { get; set; } = "";

        /// <summary>界面主题："light" 或 "dark"。</summary>
        public string Theme { get; set; } = "light";

        /// <summary>文件列表显示的列（可选值：type/size/mtime/ctime/enc）。</summary>
        public List<string> Columns { get; set; } = new() { "type", "size", "mtime" }; // 默认三列（前端 DEFAULT_COLUMNS）

    // ---------- 窗口位置与大小（关闭时保存，下次打开还原）----------
    public int WindowX { get; set; }
    public int WindowY { get; set; }
    public int WindowW { get; set; }
    public int WindowH { get; set; }
    public bool WindowMaximized { get; set; }

        // —— 阶梯锁定（防暴力猜密码）：连续输错 5 次触发锁定，档位递增 ——
        /// <summary>当前连续输错密码次数（输对一次清零）。</summary>
        public int PwdFailCount { get; set; }

        /// <summary>已触发过的锁定档位（1=15 分钟，2=1 小时，3=2 小时，此后每档 +1 小时）。</summary>
        public int LockoutStage { get; set; }

        /// <summary>当前锁定截止时间（UTC ISO-8601，空 = 未锁定）。</summary>
        public string LockoutUntilUtc { get; set; } = "";

        /// <summary>配置文件路径（exe 所在目录）。</summary>
        public static string Path => AppPaths.ConfigPath;

        public static AppConfig Load()
        {
            var cfg = new AppConfig();
            try
            {
                if (File.Exists(Path))
                {
                    var js = new JavaScriptSerializer();
                    var saved = js.Deserialize<AppConfig>(File.ReadAllText(Path));
                    if (saved != null) cfg = saved;
                }
            }
            catch { /* 配置损坏 → 使用默认值 */ }

            // 防御性校正
            if (cfg.LockMinutes < 1) cfg.LockMinutes = 20;
            if (cfg.LockMode != "duration" && cfg.LockMode != "fixed") cfg.LockMode = "duration";
            if (cfg.Theme != "light" && cfg.Theme != "dark") cfg.Theme = "light";
            if (cfg.PwdFailCount < 0) cfg.PwdFailCount = 0;
            if (cfg.LockoutStage < 0) cfg.LockoutStage = 0;
            if (cfg.Columns == null || cfg.Columns.Count == 0)
                cfg.Columns = new List<string> { "type", "size", "mtime" };
            return cfg;
        }

        public void Save()
        {
            var js = new JavaScriptSerializer();
            File.WriteAllText(Path, js.Serialize(this), new UTF8Encoding(false));
        }

        /// <summary>
        /// 根据当前自动锁定配置计算本次解锁的“目标锁定时间戳”（UTC）。
        /// 定点模式：截止时间已过则拒绝解锁（返回 null + 原因），避免“永远解不了锁”的空档。
        /// </summary>
        public DateTime? ComputeLockTarget(out string error)
        {
            error = "";
            if (LockMode == "fixed")
            {
                if (string.IsNullOrEmpty(LockDeadlineUtc))
                {
                    error = "定点临时解锁模式尚未设置截止时间，请在设置中配置。";
                    return null;
                }
                if (!DateTime.TryParse(LockDeadlineUtc, null, DateTimeStyles.RoundtripKind, out var deadline))
                {
                    error = "截止时间格式无效。";
                    return null;
                }
                if (deadline <= DateTime.UtcNow)
                {
                    error = "定点临时解锁的截止时间已过，请在设置中重新选择。";
                    return null;
                }
                return deadline;
            }
            // 自定义时长模式：解锁时刻 + N 分钟（默认 20，最小 1，上限 7 天）
            int minutes = Math.Max(1, Math.Min(LockMinutes, 10080));
            return DateTime.UtcNow.AddMinutes(minutes);
        }
    }
}
