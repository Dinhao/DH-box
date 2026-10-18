using System;
using System.IO;
using System.Text;

namespace SecretVault
{
    /// <summary>
    /// 本地文本日志（vault.log，与 exe 同目录，隐藏属性）。
    /// 记录历次解锁时间、锁定、操作结果、配置变更等事件。
    /// 安全约定：绝不记录明文密码、找回答案等敏感信息。
    /// </summary>
    public static class Logger
    {
        private static readonly object Gate = new();

        public static string LogFilePath => AppPaths.LogPath;

        /// <summary>追加一条日志（线程安全，失败不影响主流程）。</summary>
        public static void Write(string category, string message)
        {
            try
            {
                lock (Gate)
                {
                    // 注意：不设置 Hidden 属性——某些环境（安全软件/沙箱过滤）会拒绝向隐藏文件写入
                    string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{category}] {message}";
                    File.AppendAllText(LogFilePath, line + Environment.NewLine, new UTF8Encoding(false));
                }
            }
            catch { }
        }

        /// <summary>读取最近 maxLines 行（最多回看文件尾部 256KB，避免大日志卡顿）。</summary>
        public static string ReadTail(int maxLines)
        {
            lock (Gate)
            {
                try
                {
                    if (!File.Exists(LogFilePath)) return "（暂无日志）";
                    using var fs = new FileStream(LogFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    long pos = Math.Max(0, fs.Length - 256 * 1024);
                    fs.Seek(pos, SeekOrigin.Begin);
                    using var sr = new StreamReader(fs, Encoding.UTF8);
                    string text = sr.ReadToEnd();
                    if (pos > 0)
                    {
                        int i = text.IndexOf('\n');
                        if (i >= 0) text = text.Substring(i + 1); // 丢弃可能被截断的第一行
                    }
                    string[] lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length <= maxLines) return string.Join(Environment.NewLine, lines);
                    var tail = new string[maxLines];
                    Array.Copy(lines, lines.Length - maxLines, tail, 0, maxLines);
                    return string.Join(Environment.NewLine, tail);
                }
                catch (Exception ex) { return $"（日志读取失败：{ex.Message}）"; }
            }
        }

        /// <summary>清空日志。</summary>
        public static void Clear()
        {
            lock (Gate)
            {
                try { File.Delete(LogFilePath); } catch { }
            }
        }
    }
}
