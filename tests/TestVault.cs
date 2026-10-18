// DH-BOX 核心逻辑测试（控制台程序，不涉及 UI）。
// 覆盖：创建/解锁/拒绝错误密码、条目级导入导出往返一致（中文名/空目录/大文件）、
//       新建文件夹、重命名（含目录前缀）、复制、移动、删除（含子树）、回写、
//       修改密码、密码找回、篡改拦截、日志、阶梯锁定策略、旧版容器(v1)兼容读取与升级。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SecretVault;

internal static class TestMain
{
    private static int fails;
    private static string tmpRoot = "";

    private static void Check(bool ok, string name)
    {
        Console.WriteLine((ok ? "[PASS] " : "[FAIL] ") + name);
        if (!ok) fails++;
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        using var r = RandomNumberGenerator.Create();
        r.GetBytes(b);
        return b;
    }

    private static void WriteLocal(string path, byte[] data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
    }

    private static byte[] ReadLocal(string path) => File.ReadAllBytes(path);

    /// <summary>递归比对两个本地目录（文件内容 + 目录结构，空目录也算）。</summary>
    private static Dictionary<string, byte[]> Collect(string root)
    {
        var d = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var f in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            d[f.Substring(root.Length + 1)] = File.ReadAllBytes(f);
        foreach (var dir in Directory.GetDirectories(root, "*", SearchOption.AllDirectories))
            d[dir.Substring(root.Length + 1) + "/"] = Array.Empty<byte>();
        return d;
    }

    /// <summary>把整个保险箱导出到本地目录，便于与源目录比对。</summary>
    private static void ExportAll(string vault, MasterKeys mk, string dest)
    {
        foreach (var e in VaultFile.ListEntries(vault))
        {
            if (!e.IsFile) { Directory.CreateDirectory(Path.Combine(dest, e.Name.Replace('/', '\\'))); continue; }
            VaultFile.ExtractFile(vault, mk, e.Name, Path.Combine(dest, e.Name.Replace('/', '\\')));
        }
    }

    /// <summary>翻转容器中第一个文件条目密文区的 1 个字节，模拟篡改。</summary>
    private static void Tamper(string path)
    {
        var body = VaultContainer.ReadBody(path);
        var e = body.Entries.First(x => x.IsFile);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite);
        long off = e.DataOffset + 40;
        fs.Seek(off, SeekOrigin.Begin);
        int b = fs.ReadByte();
        fs.Seek(off, SeekOrigin.Begin);
        fs.WriteByte((byte)(b ^ 0xFF));
    }

    /// <summary>构造一个旧版(v1)容器：相同头部 + 无时间戳字段的条目区，用于验证兼容读取。</summary>
    private static void ConvertToLegacyV1(string v2Path, string v1Path)
    {
        var body = VaultContainer.ReadBody(v2Path);
        using var src = File.OpenRead(v2Path);
        using var dst = new FileStream(v1Path, FileMode.Create, FileAccess.Write);
        using var w = new BinaryWriter(dst, Encoding.UTF8);
        VaultContainer.WriteHeader(w, body.Header, VaultContainer.VersionLegacy); // 版本号写回 1
        w.Write(body.Entries.Count);
        foreach (var e in body.Entries)
        {
            w.Write((byte)(e.IsFile ? 1 : 2));
            var nameBytes = Encoding.UTF8.GetBytes(e.Name);
            w.Write(nameBytes.Length);
            w.Write(nameBytes);
            if (e.IsFile)
            {
                w.Write(e.PlainLength);
                src.Seek(e.DataOffset, SeekOrigin.Begin);
                CryptoUtil.Copy(src, dst, e.SealedLength);
            }
        }
        w.Flush();
        dst.Flush(true);
    }

    private static int Main()
    {
        tmpRoot = Path.Combine(Path.GetTempPath(), "dhboxtest_" + Guid.NewGuid().ToString("N"));
        try
        {
            string vault = Path.Combine(tmpRoot, "DH-BOX.vault");
            string local = Path.Combine(tmpRoot, "local");
            string export = Path.Combine(tmpRoot, "export");

            // 1. 创建与解锁
            VaultFile.Create(vault, "password123");
            Check(File.Exists(vault) && VaultFile.LooksLikeVault(vault), "创建容器");
            Check(VaultFile.TryUnlock(vault, "wrong-pass", out var err) is null, $"错误密码被拒绝（{err}）");
            var mk = VaultFile.TryUnlock(vault, "password123", out err);
            Check(mk != null, "正确密码解锁");
            Check(VaultFile.ListEntries(vault).Count == 0, "空容器无条目");

            // 2. 导入单个文件（中文名）并导出比对
            WriteLocal(Path.Combine(local, "说明 文档.txt"), Encoding.UTF8.GetBytes("你好，保险箱！"));
            Check(VaultFile.ImportFiles(vault, mk!, new[] { Path.Combine(local, "说明 文档.txt") }, "") == 1, "导入单个文件");
            var entries = VaultFile.ListEntries(vault);
            Check(entries.Any(e => e.IsFile && e.Name == "说明 文档.txt"), "条目表包含中文文件名");
            var docEntry = entries.First(e => e.Name == "说明 文档.txt");
            Check(docEntry.PlainLength > 0, "条目记录明文长度");
            Check(docEntry.Modified != DateTime.MinValue, "条目记录修改时间");
            string outFile = Path.Combine(export, "out.txt");
            VaultFile.ExtractFile(vault, mk!, "说明 文档.txt", outFile);
            Check(Encoding.UTF8.GetString(ReadLocal(outFile)) == "你好，保险箱！", "导出内容一致");

            // 3. 新建文件夹 + 导入到指定目录
            VaultFile.CreateFolder(vault, mk!, "", "工作资料");
            Check(VaultFile.ListEntries(vault).Any(e => !e.IsFile && e.Name == "工作资料"), "新建文件夹");
            WriteLocal(Path.Combine(local, "报告.pdf"), RandomBytes(1234));
            VaultFile.ImportFiles(vault, mk!, new[] { Path.Combine(local, "报告.pdf") }, "工作资料");
            Check(VaultFile.ListEntries(vault).Any(e => e.Name == "工作资料/报告.pdf"), "导入到子目录");

            // 4. 导入整个本地目录（含嵌套子目录、空目录、3MB 大文件），全部导出后比对
            WriteLocal(Path.Combine(local, "资料夹", "深层", "data.bin"), RandomBytes(3 * 1024 * 1024));
            WriteLocal(Path.Combine(local, "资料夹", "readme.txt"), Encoding.UTF8.GetBytes("readme"));
            Directory.CreateDirectory(Path.Combine(local, "资料夹", "空目录"));
            int imported = VaultFile.ImportDirectory(vault, mk!, Path.Combine(local, "资料夹"), "");
            Check(imported == 2, $"导入整个目录（{imported} 个文件）");
            ExportAll(vault, mk!, export);
            Check(File.Exists(Path.Combine(export, "资料夹", "深层", "data.bin")), "嵌套文件已导出");
            Check(Directory.Exists(Path.Combine(export, "资料夹", "空目录")), "空目录已保留");
            Check(ReadLocal(Path.Combine(export, "资料夹", "深层", "data.bin"))
                .SequenceEqual(ReadLocal(Path.Combine(local, "资料夹", "深层", "data.bin"))), "3MB 大文件往返一致");

            // 5. 重命名（目录整体改前缀）
            VaultFile.RenameEntry(vault, mk!, "工作资料", "重要资料");
            var afterRename = VaultFile.ListEntries(vault);
            Check(afterRename.Any(e => e.Name == "重要资料"), "重命名目录");
            Check(afterRename.Any(e => e.Name == "重要资料/报告.pdf"), "目录内容随前缀改名");

            // 6. 复制与移动
            VaultFile.CreateFolder(vault, mk!, "", "收件箱");
            VaultFile.CopyEntries(vault, mk!, new[] { "重要资料/报告.pdf" }, "收件箱");
            var afterCopy = VaultFile.ListEntries(vault);
            Check(afterCopy.Any(e => e.Name == "收件箱/报告.pdf"), "复制到目标目录");
            Check(afterCopy.Any(e => e.Name == "重要资料/报告.pdf"), "复制后源文件仍在");
            VaultFile.MoveEntries(vault, mk!, new[] { "收件箱/报告.pdf" }, "");
            var afterMove = VaultFile.ListEntries(vault);
            Check(afterMove.Any(e => e.Name == "报告.pdf"), "移动到根目录");
            Check(!afterMove.Any(e => e.Name == "收件箱/报告.pdf"), "移动后源条目已删除");

            // 7. 回写（模拟打开编辑后保存）
            string edited = Path.Combine(local, "报告_edited.pdf");
            WriteLocal(edited, RandomBytes(2048));
            VaultFile.ReplaceFileFrom(vault, mk!, "报告.pdf", edited);
            string reOut = Path.Combine(export, "re.txt");
            VaultFile.ExtractFile(vault, mk!, "报告.pdf", reOut);
            Check(ReadLocal(reOut).SequenceEqual(ReadLocal(edited)), "回写后内容更新");

            // 8. 删除（目录连同子树）
            VaultFile.DeleteEntries(vault, mk!, new[] { "重要资料" });
            var afterDelete = VaultFile.ListEntries(vault);
            Check(!afterDelete.Any(e => e.Name == "重要资料" || e.Name.StartsWith("重要资料/")), "删除目录及其子项");

            // 9. 修改密码 / 找回
            Check(VaultFile.ChangePassword(vault, "password123", "newpass456", out err), $"修改密码：{err}");
            Check(VaultFile.TryUnlock(vault, "password123", out err) is null, "修改后旧密码失效");
            Check(VaultFile.TryUnlock(vault, "newpass456", out err) != null, "修改后新密码生效");
            Check(VaultFile.SetRecovery(vault, "newpass456", "我的小学叫什么？", "阳光小学", out err), $"设置找回：{err}");
            Check(VaultFile.ReadRecoveryQuestion(vault) == "我的小学叫什么？", "读取找回问题");
            Check(VaultFile.Recover(vault, "错误答案", "x123456", out err) is null, "错误答案被拒绝");
            var mk4 = VaultFile.Recover(vault, "阳光小学", "recovered789", out err);
            Check(mk4 != null, $"凭答案重置密码：{err}");
            Check(VaultFile.TryUnlock(vault, "recovered789", out err) != null, "找回后新密码生效");
            Check(VaultFile.ClearRecovery(vault, "recovered789", out err), "清除找回设置");

            // 10. 密码变更后条目仍然完好（头部不丢失）
            var mk5 = VaultFile.TryUnlock(vault, "recovered789", out err)!;
            var beforeEntries = VaultFile.ListEntries(vault).Select(e => e.Name).OrderBy(x => x).ToList();
            VaultFile.CreateFolder(vault, mk5, "", "触发一次重写");
            var afterEntries = VaultFile.ListEntries(vault).Where(e => e.Name != "触发一次重写")
                .Select(e => e.Name).OrderBy(x => x).ToList();
            Check(beforeEntries.SequenceEqual(afterEntries), "重写容器不改变既有条目");
            Check(VaultFile.TryUnlock(vault, "recovered789", out err) != null, "重写后密码仍有效");

            // 11. 篡改检测
            string tampered = Path.Combine(tmpRoot, "tamper.vault");
            File.Copy(vault, tampered);
            Tamper(tampered);
            bool caught = false;
            var mkT = VaultFile.TryUnlock(tampered, "recovered789", out err);
            if (mkT != null)
            {
                try
                {
                    VaultFile.ExtractFile(tampered, mkT, VaultFile.ListEntries(tampered).First(x => x.IsFile).Name,
                        Path.Combine(export, "t.bin"));
                }
                catch (CryptographicException ex) { caught = true; Console.WriteLine($"  [预期拦截] {ex.GetType().Name}"); }
                catch (InvalidDataException ex) { caught = true; Console.WriteLine($"  [预期拦截] {ex.GetType().Name}"); }
            }
            Check(caught, "篡改数据被完整性校验拦截");

            // 12. 旧版 v1 容器兼容读取与自动升级
            string v1 = Path.Combine(tmpRoot, "legacy.vault");
            ConvertToLegacyV1(vault, v1);
            Check(VaultContainer.ReadBody(v1).Version == VaultContainer.VersionLegacy, "构造旧版容器(v1)");
            var mkV1 = VaultFile.TryUnlock(v1, "recovered789", out err);
            Check(mkV1 != null, "旧版容器可正常解锁");
            var v1Entries = VaultFile.ListEntries(v1);
            Check(v1Entries.Count > 0, "旧版容器条目可读取");
            string v1out = Path.Combine(export, "legacy.bin");
            VaultFile.ExtractFile(v1, mkV1!, v1Entries.First(x => x.IsFile).Name, v1out);
            Check(File.Exists(v1out), "旧版容器文件可解密导出");
            VaultFile.CreateFolder(v1, mkV1!, "", "旧库升级测试");   // 触发重写 => 自动升级为 v2
            Check(VaultContainer.ReadBody(v1).Version == VaultContainer.Version, "旧版容器写入后升级为 v2");
            Check(VaultFile.TryUnlock(v1, "recovered789", out err) != null, "升级后仍可用原密码解锁");

            // 13. 日志
            Logger.Write("测试", "测试日志行");
            Check(Logger.ReadTail(10).Contains("测试日志行"), "日志写入与读取");

            // ==================== 14. 阶梯式锁定策略 ====================
            var lcfg = new AppConfig();
            for (int i = 1; i <= 4; i++)
            {
                LockoutPolicy.OnFailure(lcfg);
                Check(!LockoutPolicy.IsLocked(lcfg), $"连续第 {i} 次错误未锁定");
            }
            LockoutPolicy.OnFailure(lcfg);
            Check(LockoutPolicy.IsLocked(lcfg), "连续 5 次错误触发锁定");
            Check(Math.Abs((LockoutPolicy.LockoutUntil(lcfg)!.Value - DateTime.UtcNow).TotalMinutes - 15) < 1, "首档锁定 15 分钟");
            lcfg.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(-1).ToString("o");
            Check(!LockoutPolicy.IsLocked(lcfg), "锁定期满自动解除");
            for (int i = 0; i < 5; i++) LockoutPolicy.OnFailure(lcfg);
            Check(Math.Abs((LockoutPolicy.LockoutUntil(lcfg)!.Value - DateTime.UtcNow).TotalMinutes - 60) < 1, "第二档锁定 1 小时");
            for (int i = 0; i < 5; i++) LockoutPolicy.OnFailure(lcfg);
            Check(Math.Abs((LockoutPolicy.LockoutUntil(lcfg)!.Value - DateTime.UtcNow).TotalMinutes - 120) < 1, "第三档锁定 2 小时");
            for (int i = 0; i < 5; i++) LockoutPolicy.OnFailure(lcfg);
            Check(Math.Abs((LockoutPolicy.LockoutUntil(lcfg)!.Value - DateTime.UtcNow).TotalMinutes - 180) < 1, "第四档锁定 3 小时");
            LockoutPolicy.OnSuccess(lcfg);
            Check(lcfg.PwdFailCount == 0 && lcfg.LockoutStage == 0 && !LockoutPolicy.IsLocked(lcfg), "验证成功后清零");
            for (int i = 0; i < 3; i++) LockoutPolicy.OnFailure(lcfg);
            LockoutPolicy.OnSuccess(lcfg);
            for (int i = 0; i < 4; i++) LockoutPolicy.OnFailure(lcfg);
            Check(!LockoutPolicy.IsLocked(lcfg) && lcfg.PwdFailCount == 4, "输对一次后重新累计");

            Console.WriteLine();
            Console.WriteLine(fails == 0 ? "全部通过 ✔" : $"失败项：{fails}");
        }
        catch (Exception ex)
        {
            fails++;
            Console.WriteLine($"[FAIL] 未预期异常：{ex}");
        }
        finally
        {
            try { Directory.Delete(tmpRoot, true); } catch { }
            try { File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vault.log")); } catch { }
            try { File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Vault.config")); } catch { }
        }
        return fails == 0 ? 0 : 1;
    }
}
