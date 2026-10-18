using System;
using System.IO;

namespace SecretVault
{
    /// <summary>通用小工具。</summary>
    public static class Utils
    {
        /// <summary>
        /// 递归删除目录（工作目录清理用）：
        /// 先清除只读/隐藏/系统属性再删，避免因属性导致删除失败。
        /// </summary>
        public static void DeleteTreeRobust(string? dir)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            try
            {
                foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                    try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                foreach (var d in Directory.GetDirectories(dir, "*", SearchOption.AllDirectories))
                    try { File.SetAttributes(d, FileAttributes.Normal); } catch { }
                Directory.Delete(dir, true);
            }
            catch (Exception ex)
            {
                Logger.Write("清理", $"删除目录失败：{dir}（{ex.Message}）");
            }
        }
    }
}
