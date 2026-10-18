using System;
using System.Globalization;

namespace SecretVault
{
    /// <summary>
    /// 阶梯式锁定策略（防暴力猜密码，状态持久化在 Vault.config）：
    ///   - 连续输错 5 次密码 → 触发临时锁定；
    ///   - 第 1 档锁 15 分钟；之后每触发一次档位 +1：
    ///     第 2 档 1 小时、第 3 档 2 小时、第 4 档 3 小时……依次每小时递增；
    ///   - 锁定期内一律拒绝验证（输入正确密码也不放行）；
    ///   - 锁定期满自动解除；
    ///   - 输对一次密码：清零连续错误计数与锁定档位（阶梯从头开始）。
    /// 说明：解锁密码框与系统设置的管理员验证共用同一把锁（同一凭证）。
    /// </summary>
    public static class LockoutPolicy
    {
        /// <summary>连续错误多少次触发锁定。</summary>
        public const int FailLimit = 5;

        /// <summary>锁定档位 → 分钟数：第 1 档 15 分钟；第 2 档 1 小时；第 3 档 2 小时；此后每档 +1 小时。</summary>
        public static int LockMinutes(int stage) => stage <= 1 ? 15 : (stage - 1) * 60;

        /// <summary>当前锁定截止时间（UTC）；未锁定返回 null。</summary>
        public static DateTime? LockoutUntil(AppConfig cfg)
            => DateTime.TryParse(cfg.LockoutUntilUtc, null, DateTimeStyles.RoundtripKind, out var t)
                ? t
                : (DateTime?)null;

        /// <summary>当前是否处于锁定期内。</summary>
        public static bool IsLocked(AppConfig cfg)
        {
            var t = LockoutUntil(cfg);
            return t.HasValue && t.Value > DateTime.UtcNow;
        }

        /// <summary>剩余锁定时间的友好文案；未锁定返回 null。</summary>
        public static string? RemainingText(AppConfig cfg)
        {
            var t = LockoutUntil(cfg);
            if (t is null) return null;
            var left = t.Value - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return null;
            return left.TotalHours >= 1
                ? $"{(int)left.TotalHours} 小时 {left.Minutes} 分"
                : $"{left.Minutes} 分 {left.Seconds} 秒";
        }

        /// <summary>
        /// 记录一次密码验证失败（状态即时落盘，跨进程/重启有效）。
        /// 达到 5 次连续错误即触发锁定并升档。
        /// </summary>
        public static void OnFailure(AppConfig cfg)
        {
            cfg.PwdFailCount++;
            if (cfg.PwdFailCount < FailLimit)
            {
                cfg.Save();
                return;
            }
            // 触发锁定：错误计数清零，档位 +1，按档位计算锁定时长
            cfg.PwdFailCount = 0;
            cfg.LockoutStage++;
            cfg.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(LockMinutes(cfg.LockoutStage)).ToString("o");
            cfg.Save();
        }

        /// <summary>密码验证成功：清零连续错误计数与锁定档位（阶梯从头开始）。</summary>
        public static void OnSuccess(AppConfig cfg)
        {
            if (cfg.PwdFailCount == 0 && cfg.LockoutStage == 0 && string.IsNullOrEmpty(cfg.LockoutUntilUtc))
                return; // 无状态可清，避免无谓写盘
            cfg.PwdFailCount = 0;
            cfg.LockoutStage = 0;
            cfg.LockoutUntilUtc = "";
            cfg.Save();
        }
    }
}
