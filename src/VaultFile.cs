using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SecretVault
{
    /// <summary>解密后的主密钥（64 字节 = AES-256 密钥 32B || HMAC-SHA256 密钥 32B），仅存在于内存。</summary>
    public class MasterKeys
    {
        public readonly byte[] WrapKey = new byte[CryptoUtil.WrapKeySize];

        public void Wipe() => CryptoUtil.Wipe(WrapKey);
    }

    /// <summary>基于容器路径生成进程间同步用的命名互斥量名称（同一用户会话内有效）。</summary>
    public static class VaultIds
    {
        /// <summary>路径的 SHA256 前 8 个十六进制字符。</summary>
        public static string Hash8(string? text)
        {
            using var sha = SHA256.Create();
            byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(text ?? ""));
            var sb = new StringBuilder(8);
            for (int i = 0; i < 4; i++) sb.Append(h[i].ToString("x2"));
            return sb.ToString();
        }

        /// <summary>容器读写互斥量：串行化多进程对容器的修改。</summary>
        public static string ContainerName(string vaultPath) => $"Local\\DHBOX.Container.{Hash8(vaultPath)}";

        /// <summary>程序单实例互斥量：同一保险箱同时只允许一个程序窗口（避免并发覆盖）。</summary>
        public static string AppName(string vaultPath) => $"Local\\DHBOX.App.{Hash8(vaultPath)}";
    }

    /// <summary>
    /// 保险箱条目级操作（文件加密保险库的核心）。
    ///
    /// 加密设计（信封加密，与旧版数据格式完全兼容）：
    ///   - 每个文件用“主密钥”（随机 64B，AES-256-CBC + HMAC-SHA256）密封；
    ///   - 主密钥本身用 PBKDF2(密码) 派生的包装密钥密封存入容器头；
    ///   - 修改密码只重包装主密钥，所有文件零重加密；
    ///   - 找回提示：主密钥额外用 PBKDF2(答案) 包装一份。
    ///
    /// 条目级修改（新增/删除/改名/移动/回写）统一走 Rewrite：
    ///   未变更条目的**密文原样复制**（零重加密），只有新增/修改的文件才重新密封，
    ///   整个容器“写临时文件 + 原子替换 + .bak 备份”，避免中断损坏数据。
    /// </summary>
    public static class VaultFile
    {
        public const int VersionVault = VaultContainer.Version;

        /// <summary>判断文件是否为本工具的容器（只读魔数，不修改文件）。</summary>
        public static bool LooksLikeVault(string path)
        {
            try
            {
                using var fs = File.OpenRead(path);
                var b = new byte[4];
                return fs.Read(b, 0, 4) == 4 && Encoding.ASCII.GetString(b) == VaultContainer.Magic;
            }
            catch { return false; }
        }

        /// <summary>创建新保险箱（空容器）。</summary>
        public static void Create(string path, string password)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);

            var salt = CryptoUtil.NewSalt();
            int iter = CryptoUtil.DefaultKdfIterations;
            var wk = CryptoUtil.DeriveWrapKey(password, salt, iter);
            var master = CryptoUtil.NewMasterKey();
            try
            {
                var h = new VaultContainer.VaultHeader
                {
                    Salt = salt,
                    KdfIterations = iter,
                    PwdCheck = CryptoUtil.ComputeCheck(wk, true),
                    WrapPwd = CryptoUtil.SealBytes(wk, CryptoUtil.Concat(master, CryptoUtil.MasterMagic)),
                    AnsSalt = new byte[CryptoUtil.SaltSize],   // 未设置找回：全 0
                    AnsCheck = new byte[CryptoUtil.HmacSize],
                    WrapAns = new byte[VaultContainer.WrapBlobSize],
                    Question = null,
                };
                using (EnterContainerLock(path))
                    VaultContainer.WriteNew(path, h);
            }
            finally
            {
                CryptoUtil.Wipe(wk);
                CryptoUtil.Wipe(master);
            }
        }

        /// <summary>密码解锁：验证密码并从容器头解出主密钥。失败返回 null 并给出原因。</summary>
        public static MasterKeys? TryUnlock(string path, string password, out string error)
        {
            VaultContainer.VaultHeader h;
            try { h = VaultContainer.ReadHeader(path); }
            catch (Exception ex) { error = $"读取容器失败：{ex.Message}"; return null; }
            return UnlockWithHeader(h, password, out error);
        }

        /// <summary>修改密码：校验旧密码 → 用新密码重新包装主密钥（不重加密任何文件）。</summary>
        public static bool ChangePassword(string path, string oldPwd, string newPwd, out string error)
        {
            error = "";
            using (EnterContainerLock(path))
            {
                var h = VaultContainer.ReadHeader(path);
                var mk = UnlockWithHeader(h, oldPwd, out error);
                if (mk is null) return false;
                try
                {
                    RewrapPassword(h, mk, newPwd);
                    VaultContainer.RewriteHeader(path, h);
                    return true;
                }
                finally { mk.Wipe(); }
            }
        }

        /// <summary>设置/修改密码找回提示（问题 + 答案）。答案绝不落盘明文，只存加盐哈希与包装密钥。</summary>
        public static bool SetRecovery(string path, string password, string question, string answer, out string error)
        {
            error = "";
            using (EnterContainerLock(path))
            {
                var h = VaultContainer.ReadHeader(path);
                var mk = UnlockWithHeader(h, password, out error);
                if (mk is null) return false;
                try
                {
                    var aslt = CryptoUtil.NewSalt();
                    var awk = CryptoUtil.DeriveWrapKey(answer, aslt, h.KdfIterations);
                    try
                    {
                        h.AnsSalt = aslt;
                        h.AnsCheck = CryptoUtil.ComputeCheck(awk, false);
                        h.WrapAns = CryptoUtil.SealBytes(awk, CryptoUtil.Concat(mk.WrapKey, CryptoUtil.MasterMagic));
                        h.Question = question.Trim();
                    }
                    finally { CryptoUtil.Wipe(awk); }
                    VaultContainer.RewriteHeader(path, h);
                    return true;
                }
                finally { mk.Wipe(); }
            }
        }

        /// <summary>清除密码找回设置（需保险箱密码确认身份）。</summary>
        public static bool ClearRecovery(string path, string password, out string error)
        {
            error = "";
            using (EnterContainerLock(path))
            {
                var h = VaultContainer.ReadHeader(path);
                var mk = UnlockWithHeader(h, password, out error);
                if (mk is null) return false;
                try
                {
                    h.AnsSalt = new byte[CryptoUtil.SaltSize];
                    h.AnsCheck = new byte[CryptoUtil.HmacSize];
                    h.WrapAns = new byte[VaultContainer.WrapBlobSize];
                    h.Question = null;
                    VaultContainer.RewriteHeader(path, h);
                    return true;
                }
                finally { mk.Wipe(); }
            }
        }

        /// <summary>读取找回问题（明文存在容器头，解锁前即可展示）。未设置返回 null。</summary>
        public static string? ReadRecoveryQuestion(string path)
        {
            try { return VaultContainer.ReadHeader(path).Question; }
            catch { return null; }
        }

        /// <summary>
        /// 凭找回答案重置密码：答案正确 → 解开主密钥 → 用新密码重新包装。
        /// 返回的主密钥可直接用于本次解锁会话（调用方用完必须 Wipe）。
        /// </summary>
        public static MasterKeys? Recover(string path, string answer, string newPassword, out string error)
        {
            error = "";
            using (EnterContainerLock(path))
            {
                var h = VaultContainer.ReadHeader(path);
                if (!h.HasRecovery) { error = "尚未设置密码找回提示，无法自助找回。"; return null; }
                try
                {
                    var awk = CryptoUtil.DeriveWrapKey(answer, h.AnsSalt, h.KdfIterations);
                    try
                    {
                        if (!CryptoUtil.FixedTimeEquals(CryptoUtil.ComputeCheck(awk, false), h.AnsCheck))
                        { error = "找回答案不正确。"; return null; }
                        var blob = CryptoUtil.OpenBytes(awk, h.WrapAns, CryptoUtil.MasterBlobSize);
                        if (!CryptoUtil.HasMasterMagic(blob))
                        { error = "找回数据校验失败，容器可能已损坏。"; return null; }
                        var mk = new MasterKeys();
                        Buffer.BlockCopy(blob, 0, mk.WrapKey, 0, CryptoUtil.WrapKeySize);
                        CryptoUtil.Wipe(blob);

                        RewrapPassword(h, mk, newPassword);  // 用新密码重新包装主密钥
                        VaultContainer.RewriteHeader(path, h);
                        return mk;
                    }
                    finally { CryptoUtil.Wipe(awk); }
                }
                catch (CryptographicException ex) { error = $"找回数据损坏，无法恢复（{ex.Message}）。"; return null; }
                catch (Exception ex) { error = $"找回失败：{ex.Message}"; return null; }
            }
        }

        // ==================== 条目级操作 ====================

        /// <summary>读取条目表（不解密文件内容）。</summary>
        public static List<VaultEntry> ListEntries(string vaultPath)
            => VaultContainer.ReadBody(vaultPath).Entries;

        /// <summary>把容器内的一个文件解密到本地路径（打开 / 导出用）。</summary>
        public static void ExtractFile(string vaultPath, MasterKeys mk, string entryPath, string destLocalPath)
        {
            var body = VaultContainer.ReadBody(vaultPath);
            var e = body.Entries.FirstOrDefault(x => x.IsFile && x.Name == entryPath)
                ?? throw new FileNotFoundException($"保险箱中不存在文件：{entryPath}");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destLocalPath))!);
            using var src = File.OpenRead(vaultPath);
            using var dst = new FileStream(destLocalPath, FileMode.Create, FileAccess.Write);
            src.Seek(e.DataOffset, SeekOrigin.Begin);
            CryptoUtil.OpenStream(src, dst, mk.WrapKey, e.PlainLength);
            dst.Flush(true);
            // 还原时间戳（有记录时）
            try
            {
                if (e.Modified != DateTime.MinValue) File.SetLastWriteTime(destLocalPath, e.Modified);
                if (e.Created != DateTime.MinValue) File.SetCreationTime(destLocalPath, e.Created);
            }
            catch { }
        }

        /// <summary>导入若干本地文件到容器内的目标目录（“目录”为空串表示根）。</summary>
        public static int ImportFiles(string vaultPath, MasterKeys mk, IEnumerable<string> localFiles, string destDir)
        {
            var files = localFiles.Where(File.Exists).ToList();
            if (files.Count == 0) return 0;
            int imported = 0;
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var items = ExistingItems(body);
                // 只与“同一目录下的兄弟项”比较重名
                var leaves = new HashSet<string>(
                    items.Where(i => ParentOf(i.Name) == destDir).Select(i => LeafOf(i.Name)),
                    StringComparer.OrdinalIgnoreCase);
                foreach (var f in files)
                {
                    var fi = new FileInfo(f);
                    string leaf = UniqueName(leaves, fi.Name, false);
                    leaves.Add(leaf);
                    items.Add(new OutItem
                    {
                        IsFile = true,
                        Name = JoinPath(destDir, leaf),
                        PlainLength = fi.Length,
                        Modified = fi.LastWriteTime,
                        Created = fi.CreationTime,
                        SealLocalFile = f,
                    });
                    imported++;
                }
                return items;
            });
            return imported;
        }

        /// <summary>导入整个本地目录（递归，保留空目录）到容器内目标目录。</summary>
        public static int ImportDirectory(string vaultPath, MasterKeys mk, string localDir, string destDir)
        {
            var files = new List<(string Local, string RelDir)>();
            var dirs = new List<string>();
            CollectLocal(localDir, "", files, dirs);
            int imported = 0;
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var items = ExistingItems(body);
                var leaves = new HashSet<string>(
                    items.Where(i => ParentOf(i.Name) == destDir).Select(i => LeafOf(i.Name)),
                    StringComparer.OrdinalIgnoreCase);
                // 顶层目录条目（本地目录内部名称本身唯一，无需逐项改名；保留空目录结构）
                string rootLeaf = UniqueName(leaves, Path.GetFileName(localDir.TrimEnd('\\', '/')), true);
                leaves.Add(rootLeaf);
                string rootName = JoinPath(destDir, rootLeaf);
                var now = DateTime.Now;
                items.Add(new OutItem { IsFile = false, Name = rootName, Modified = now, Created = now });
                foreach (var d in dirs)
                    items.Add(new OutItem { IsFile = false, Name = rootName + "/" + d, Modified = now, Created = now });
                foreach (var (local, relDir) in files)
                {
                    var fi = new FileInfo(local);
                    string full = rootName + "/" + (relDir.Length == 0 ? "" : relDir + "/") + fi.Name;
                    items.Add(new OutItem
                    {
                        IsFile = true,
                        Name = full,
                        PlainLength = fi.Length,
                        Modified = fi.LastWriteTime,
                        Created = fi.CreationTime,
                        SealLocalFile = local,
                    });
                    imported++;
                }
                return items;
            });
            return imported;
        }

        /// <summary>在指定目录下新建文件夹。</summary>
        public static void CreateFolder(string vaultPath, MasterKeys mk, string parentDir, string name)
        {
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var items = ExistingItems(body);
                var leaves = new HashSet<string>(
                    items.Where(i => ParentOf(i.Name) == parentDir).Select(i => LeafOf(i.Name)),
                    StringComparer.OrdinalIgnoreCase);
                string full = JoinPath(parentDir, UniqueName(leaves, name.Trim(), true));
                var now = DateTime.Now;
                items.Add(new OutItem { IsFile = false, Name = full, Modified = now, Created = now });
                return items;
            });
        }

        /// <summary>删除条目（目录会连同其下所有内容一起删除）。</summary>
        public static void DeleteEntries(string vaultPath, MasterKeys mk, IEnumerable<string> entryPaths)
        {
            var targets = entryPaths.ToList();
            if (targets.Count == 0) return;
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var items = new List<OutItem>();
                foreach (var e in body.Entries)
                {
                    if (targets.Any(t => IsSameOrUnder(e.Name, t))) continue; // 被删除或位于被删除目录之下
                    items.Add(FromExisting(e));
                }
                return items;
            });
        }

        /// <summary>重命名条目（目录会连同其下所有内容一起改名；重名自动编号）。</summary>
        public static void RenameEntry(string vaultPath, MasterKeys mk, string entryPath, string newName)
        {
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var target = body.Entries.FirstOrDefault(x => x.Name == entryPath)
                    ?? throw new FileNotFoundException($"条目不存在：{entryPath}");
                string parent = target.ParentDir;
                // 兄弟重名检查（排除自身）
                var siblings = new HashSet<string>(
                    body.Entries.Where(x => x.ParentDir == parent && x.Name != entryPath).Select(x => x.Leaf),
                    StringComparer.OrdinalIgnoreCase);
                string leaf = UniqueName(siblings, SanitizeName(newName), target.IsFile);
                string newPath = JoinPath(parent, leaf);

                var items = new List<OutItem>();
                foreach (var e in body.Entries)
                {
                    if (e.Name == entryPath)
                    {
                        var it = FromExisting(e);
                        it.Name = newPath;
                        if (!e.IsFile) { it.Modified = DateTime.Now; }
                        items.Add(it);
                    }
                    else if (!target.IsFile && IsUnder(e.Name, entryPath))
                    {
                        // 目录内容：整体改前缀
                        var it = FromExisting(e);
                        it.Name = newPath + e.Name.Substring(entryPath.Length);
                        items.Add(it);
                    }
                    else items.Add(FromExisting(e));
                }
                return items;
            });
        }

        /// <summary>复制条目到目标目录（目录递归复制；重名自动编号；密文直接复制，零重加密）。</summary>
        public static void CopyEntries(string vaultPath, MasterKeys mk, IEnumerable<string> entryPaths, string destDir)
        {
            MoveOrCopy(vaultPath, mk, entryPaths, destDir, move: false);
        }

        /// <summary>移动条目到目标目录（剪切/粘贴）。</summary>
        public static void MoveEntries(string vaultPath, MasterKeys mk, IEnumerable<string> entryPaths, string destDir)
        {
            MoveOrCopy(vaultPath, mk, entryPaths, destDir, move: true);
        }

        /// <summary>用本地文件内容回写（替换）容器中的某个文件条目（打开编辑后保存用）。</summary>
        public static void ReplaceFileFrom(string vaultPath, MasterKeys mk, string entryPath, string localPath)
        {
            var fi = new FileInfo(localPath);
            if (!fi.Exists) throw new FileNotFoundException("本地文件不存在：" + localPath);
            Rewrite(vaultPath, mk, (body, src) =>
            {
                var items = new List<OutItem>();
                bool found = false;
                foreach (var e in body.Entries)
                {
                    if (e.Name == entryPath && e.IsFile)
                    {
                        found = true;
                        items.Add(new OutItem
                        {
                            IsFile = true,
                            Name = e.Name,
                            PlainLength = fi.Length,
                            Modified = fi.LastWriteTime,
                            Created = e.Created == DateTime.MinValue ? fi.CreationTime : e.Created,
                            SealLocalFile = localPath,
                        });
                    }
                    else items.Add(FromExisting(e));
                }
                if (!found) throw new FileNotFoundException($"保险箱中不存在文件：{entryPath}");
                return items;
            });
        }

        // ==================== 内部实现 ====================

        /// <summary>Rewrite 的输出条目：要么密文原样复制，要么从本地文件重新密封。</summary>
        private class OutItem
        {
            public bool IsFile;
            public string Name = "";
            public long PlainLength;
            public DateTime Modified;
            public DateTime Created;
            public VaultEntry? CopyFrom;      // 密文原样复制（容器内已加密的数据）
            public string? SealLocalFile;     // 从该本地文件读取并密封写入
        }

        /// <summary>把容器内容整体重写为指定的条目集合（未变更条目密文直复制）。</summary>
        private static void Rewrite(string vaultPath, MasterKeys mk, Func<VaultBody, FileStream, List<OutItem>> transform)
        {
            using (EnterContainerLock(vaultPath))
            {
                var body = VaultContainer.ReadBody(vaultPath);
                string tmp = vaultPath + ".tmp";
                using (var src = File.OpenRead(vaultPath))
                using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write))
                using (var w = new BinaryWriter(dst, Encoding.UTF8))
                {
                    var items = transform(body, src);
                    VaultContainer.WriteHeader(w, body.Header);   // 保留当前头部（密码/找回设置不变）
                    w.Write(items.Count);
                    foreach (var it in items)
                    {
                        var meta = new VaultEntry
                        {
                            Name = it.Name,
                            IsFile = it.IsFile,
                            PlainLength = it.PlainLength,
                            Modified = it.Modified,
                            Created = it.Created,
                        };
                        VaultContainer.WriteEntryMeta(w, meta);
                        if (!it.IsFile) continue;

                        if (it.CopyFrom != null)
                        {
                            // 未变更：密文原样复制（不解密、不重加密）
                            src.Seek(it.CopyFrom.DataOffset, SeekOrigin.Begin);
                            CryptoUtil.Copy(src, dst, it.CopyFrom.SealedLength);
                        }
                        else
                        {
                            using var lf = File.OpenRead(it.SealLocalFile!);
                            if (lf.Length != it.PlainLength) throw new IOException($"文件在写入过程中被修改：{it.SealLocalFile}");
                            CryptoUtil.SealStream(lf, dst, mk.WrapKey, it.PlainLength);
                        }
                    }
                    w.Flush();
                    dst.Flush(true);
                }
                VaultContainer.CommitTemp(tmp, vaultPath);
            }
        }

        private static List<OutItem> ExistingItems(VaultBody body)
            => body.Entries.Select(FromExisting).ToList();

        private static OutItem FromExisting(VaultEntry e) => new()
        {
            IsFile = e.IsFile,
            Name = e.Name,
            PlainLength = e.PlainLength,
            Modified = e.Modified,
            Created = e.Created,
            CopyFrom = e.IsFile ? e : null,
        };

        /// <summary>复制/移动条目的公共实现（密文直复制；移动 = 复制 + 删除原条目）。</summary>
        private static void MoveOrCopy(string vaultPath, MasterKeys mk, IEnumerable<string> entryPaths, string destDir, bool move)
        {
            var targets = entryPaths.Distinct().ToList();
            if (targets.Count == 0) return;
            Rewrite(vaultPath, mk, (body, src) =>
            {
                // 禁止把目录移动/复制到它自己的子目录里
                foreach (var t in targets)
                {
                    var srcEntry = body.Entries.FirstOrDefault(x => x.Name == t);
                    if (srcEntry is { IsFile: false } && IsSameOrUnder(destDir, t))
                        throw new InvalidOperationException("不能把文件夹移动/复制到它自己的子目录中。");
                }

                var items = new List<OutItem>();
                // 先放入未被移动/删除的既有条目
                foreach (var e in body.Entries)
                {
                    if (move && targets.Any(t => IsSameOrUnder(e.Name, t))) continue;
                    items.Add(FromExisting(e));
                }

                // 目标目录下的兄弟名称集合（随新增条目实时更新，避免重名）
                var destLeaves = new HashSet<string>(
                    items.Where(i => ParentOf(i.Name) == destDir).Select(i => LeafOf(i.Name)),
                    StringComparer.OrdinalIgnoreCase);
                foreach (var t in targets)
                {
                    var root = body.Entries.FirstOrDefault(x => x.Name == t)
                        ?? throw new FileNotFoundException($"条目不存在：{t}");
                    // 条目自身先放入（与目标目录下的兄弟项比较重名）
                    string leaf = UniqueName(destLeaves, root.Leaf, root.IsFile);
                    destLeaves.Add(leaf);
                    string newName = JoinPath(destDir, leaf);
                    var copyRoot = FromExisting(root);
                    copyRoot.Name = newName;
                    items.Add(copyRoot);

                    // 目录内容整体改前缀（新目录名已保证唯一，内部结构原样保留）
                    if (!root.IsFile)
                    {
                        foreach (var e in body.Entries.Where(x => IsUnder(x.Name, t)))
                        {
                            var it = FromExisting(e);
                            it.Name = newName + e.Name.Substring(t.Length);
                            items.Add(it);
                        }
                    }
                }
                return items;
            });
        }

        /// <summary>递归收集本地目录中的文件与（相对）子目录，保留空目录。</summary>
        private static void CollectLocal(string dir, string rel, List<(string Local, string RelDir)> files, List<string> dirs)
        {
            foreach (var d in Directory.GetDirectories(dir))
            {
                try
                {
                    if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; // 跳过符号链接/联接点
                }
                catch { continue; }
                string sub = rel.Length == 0 ? Path.GetFileName(d) : rel + "/" + Path.GetFileName(d);
                dirs.Add(sub);
                CollectLocal(d, sub, files, dirs);
            }
            foreach (var f in Directory.GetFiles(dir))
            {
                try
                {
                    if ((File.GetAttributes(f) & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }
                files.Add((f, rel));
            }
        }

        /// <summary>
        /// 名称唯一化（与界面原型一致：name - 副本、name - 副本 (2) …）。
        /// siblingLeaves 为“同一父目录下的兄弟名称集合”（不含完整路径）。
        /// </summary>
        private static string UniqueName(HashSet<string> siblingLeaves, string name, bool isDir)
        {
            string wanted = SanitizeName(name);
            if (wanted.Length == 0) wanted = isDir ? "新建文件夹" : "未命名";

            if (!siblingLeaves.Contains(wanted)) return wanted;

            string stem = wanted, ext = "";
            if (!isDir)
            {
                int dot = wanted.LastIndexOf('.');
                if (dot > 0) { stem = wanted.Substring(0, dot); ext = wanted.Substring(dot); }
            }
            for (int k = 1; k < 10000; k++)
            {
                string candidate = stem + " - 副本" + (k == 1 ? "" : $" ({k})") + ext;
                if (!siblingLeaves.Contains(candidate)) return candidate;
            }
            return stem + " - 副本" + DateTime.Now.Ticks;
        }

        /// <summary>完整条目路径的最后一段（显示名称）。</summary>
        private static string LeafOf(string path) => path.Substring(path.LastIndexOf('/') + 1);

        /// <summary>完整条目路径的父目录（根目录返回空串）。</summary>
        private static string ParentOf(string path)
        {
            int i = path.LastIndexOf('/');
            return i < 0 ? "" : path.Substring(0, i);
        }

        /// <summary>清理名称中的非法字符（容器内使用 '/' 作为分隔符）。</summary>
        private static string SanitizeName(string name)
        {
            name = (name ?? "").Trim();
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name.Replace('/', '_').Trim();
        }

        private static string JoinPath(string dir, string leaf)
            => string.IsNullOrEmpty(dir) ? leaf : dir.TrimEnd('/') + "/" + leaf;

        /// <summary>path 是否等于 root 或位于 root 之下。</summary>
        private static bool IsSameOrUnder(string path, string root)
            => path.Equals(root, StringComparison.OrdinalIgnoreCase)
               || path.StartsWith(root + "/", StringComparison.OrdinalIgnoreCase);

        private static bool IsUnder(string path, string root)
            => path.StartsWith(root + "/", StringComparison.OrdinalIgnoreCase);

        /// <summary>基于已读出的头部做密码校验与主密钥解包。</summary>
        private static MasterKeys? UnlockWithHeader(VaultContainer.VaultHeader h, string password, out string error)
        {
            error = "";
            try
            {
                var wk = CryptoUtil.DeriveWrapKey(password, h.Salt, h.KdfIterations);
                try
                {
                    if (!CryptoUtil.FixedTimeEquals(CryptoUtil.ComputeCheck(wk, true), h.PwdCheck))
                    { error = "密码错误。"; return null; }

                    var blob = CryptoUtil.OpenBytes(wk, h.WrapPwd, CryptoUtil.MasterBlobSize);
                    if (!CryptoUtil.HasMasterMagic(blob))
                    { error = "主密钥校验失败，容器可能已损坏。"; return null; }

                    var mk = new MasterKeys();
                    Buffer.BlockCopy(blob, 0, mk.WrapKey, 0, CryptoUtil.WrapKeySize);
                    CryptoUtil.Wipe(blob);
                    return mk;
                }
                finally { CryptoUtil.Wipe(wk); }
            }
            catch (CryptographicException ex) { error = $"密码错误或容器数据损坏（{ex.Message}）。"; return null; }
            catch (Exception ex) { error = $"读取容器失败：{ex.Message}"; return null; }
        }

        /// <summary>用新密码重新包装主密钥（新盐、新包装），更新头部字段。</summary>
        private static void RewrapPassword(VaultContainer.VaultHeader h, MasterKeys mk, string newPwd)
        {
            var ns = CryptoUtil.NewSalt();
            var nwk = CryptoUtil.DeriveWrapKey(newPwd, ns, h.KdfIterations);
            try
            {
                h.Salt = ns;
                h.PwdCheck = CryptoUtil.ComputeCheck(nwk, true);
                h.WrapPwd = CryptoUtil.SealBytes(nwk, CryptoUtil.Concat(mk.WrapKey, CryptoUtil.MasterMagic));
            }
            finally { CryptoUtil.Wipe(nwk); }
        }

        /// <summary>进入容器写互斥区（返回 IDisposable，退出 using 时释放）。</summary>
        private static IDisposable EnterContainerLock(string path)
        {
            var m = new Mutex(false, VaultIds.ContainerName(path));
            try { m.WaitOne(TimeSpan.FromSeconds(30)); }
            catch (AbandonedMutexException ex)
            {
                Logger.Write("保险库", $"接管被遗弃的容器互斥量：{ex.Message}");
            }
            return new MutexReleaser(m);
        }

        /// <summary>Mutex 释放包装器：Dispose 时显式 ReleaseMutex 并关闭句柄。</summary>
        private sealed class MutexReleaser : IDisposable
        {
            private readonly Mutex _m;
            public MutexReleaser(Mutex m) => _m = m;
            public void Dispose()
            {
                try { _m.ReleaseMutex(); } catch { }
                try { _m.Dispose(); } catch { }
            }
        }
    }
}
