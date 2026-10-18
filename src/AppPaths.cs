using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace SecretVault
{
    /// <summary>
    /// 程序路径约定（便携绿色设计）：
    ///  - 保险库容器、Vault.config、vault.log 一律固定在 exe 所在目录
    ///    （以“程序集实际位置”为准，不依赖工作目录、快捷方式起始位置）；
    ///  - 打开文件用的临时解密目录在系统临时目录（退出/锁定时自动清理）。
    /// </summary>
    public static class AppPaths
    {
        /// <summary>exe 所在目录（保险库默认创建于此，配置与日志也在此）。</summary>
        public static string ExeDir =>
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();

        /// <summary>配置文件路径。</summary>
        public static string ConfigPath => Path.Combine(ExeDir, "Vault.config");

        /// <summary>日志文件路径。</summary>
        public static string LogPath => Path.Combine(ExeDir, "vault.log");

        /// <summary>默认保险库容器文件名（固定创建在 exe 同目录，无需选择位置）。</summary>
        public const string VaultFileName = "DH-BOX.vault";

        /// <summary>默认保险库容器完整路径。</summary>
        public static string DefaultVaultPath => Path.Combine(ExeDir, VaultFileName);

        /// <summary>
        /// 查找 exe 同目录下已存在的保险库容器：
        ///   1) DH-BOX.vault；
        ///   2) 任意 *.vault；
        ///   3) 兼容旧版伪装容器（名字形如 “我的保险箱.{GUID}”，按文件魔数识别）。
        /// 用于升级旧数据：把新版程序放到旧保险库目录即可直接继续使用原数据与密码。
        /// </summary>
        public static string? FindExistingVault()
        {
            try
            {
                if (File.Exists(DefaultVaultPath)) return DefaultVaultPath;

                var anyVault = Directory.GetFiles(ExeDir, "*.vault").OrderBy(f => f).FirstOrDefault();
                if (anyVault != null) return anyVault;

                // 旧版容器形如 “我的保险箱.{F3A1C2B5-…}”，用魔数确认
                foreach (var f in Directory.GetFiles(ExeDir, "*.{*"))
                    if (VaultFile.LooksLikeVault(f)) return f;
                return null;
            }
            catch { return null; }
        }
    }
}
