using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecretVault
{
    /// <summary>保险箱内的一个条目（文件或目录）。</summary>
    public class VaultEntry
    {
        /// <summary>容器内相对路径，'/' 分隔（例如 "工作资料/合同.pdf"）。</summary>
        public string Name = "";

        /// <summary>是否为文件（false = 目录）。</summary>
        public bool IsFile;

        /// <summary>明文长度（仅文件有效）。</summary>
        public long PlainLength;

        /// <summary>修改时间（本地时间；旧容器无此字段时为 DateTime.MinValue）。</summary>
        public DateTime Modified;

        /// <summary>创建时间（本地时间；旧容器无此字段时为 DateTime.MinValue）。</summary>
        public DateTime Created;

        /// <summary>（内部）sealed 密文在容器内的起始偏移。</summary>
        internal long DataOffset;

        /// <summary>（内部）sealed 密文总长度（IV + 密文 + MAC）。</summary>
        internal long SealedLength;

        /// <summary>路径最后一段（显示名称）。</summary>
        public string Leaf => Name.Substring(Name.LastIndexOf('/') + 1);

        /// <summary>父目录路径（根目录为空字符串）。</summary>
        public string ParentDir
        {
            get
            {
                int i = Name.LastIndexOf('/');
                return i < 0 ? "" : Name.Substring(0, i);
            }
        }
    }

    /// <summary>容器完整内容（头部 + 条目表）。</summary>
    public class VaultBody
    {
        public VaultContainer.VaultHeader Header = new();
        public int Version = VaultContainer.Version;
        public List<VaultEntry> Entries = new();
    }

    /// <summary>
    /// 保险箱容器文件格式（小端序，固定头部 + 条目区）。
    ///
    /// 头部布局（v1/v2 相同）：
    ///   [0..3]    魔数 "VLT1"
    ///   [4..7]    uint 版本号（1 = 旧版条目无时间戳；2 = 条目带修改/创建时间，当前版本）
    ///   [8..23]   密码 KDF 盐 salt(16)
    ///   [24..27]  uint PBKDF2 迭代次数
    ///   [28..59]  密码校验器 pwdCheck(32) = HMAC(密码派生密钥, 标签)
    ///   [60..203] 密码包装的主密钥 wrapPwd(144) = Seal(密码派生密钥, 主密钥64B||魔数16B)
    ///   [204..219]答案 KDF 盐 ansSalt(16)（未设置找回时为全 0）
    ///   [220..251]答案校验器 ansCheck(32)（同上）
    ///   [252..395]答案包装的主密钥 wrapAns(144)（同上）
    ///   [396..399]int 找回问题 UTF-8 字节长度（0 = 未设置）
    ///   [400..]   找回问题 UTF-8 字节（明文保存，解锁前即可显示给用户）
    ///
    /// 条目区布局：
    ///   int 条目数
    ///   每条目：
    ///     byte type（1 = 文件，2 = 目录）
    ///     int  名称 UTF-8 字节长度
    ///     byte[] 名称（相对路径，'/' 分隔）
    ///     long  修改时间（UTC ticks，仅 v2）
    ///     long  创建时间（UTC ticks，仅 v2）
    ///     若为文件：long 明文长度 + sealed 数据（IV||密文||MAC，用主密钥密封）
    ///
    /// 修改容器一律“写临时文件 + File.Replace（保留 .bak 备份）”，避免写入中断损坏数据。
    /// </summary>
    public static class VaultContainer
    {
        public const string Magic = "VLT1";

        /// <summary>当前写出的版本号。</summary>
        public const int Version = 2;

        /// <summary>兼容读取的旧版本号（条目无时间戳字段）。</summary>
        public const int VersionLegacy = 1;

        /// <summary>密码/答案包装主密钥的 sealed 块固定长度：16(IV) + 96(密文=80明文PKCS7) + 32(MAC) = 144。</summary>
        public const int WrapBlobSize = CryptoUtil.IvSize
            + ((CryptoUtil.MasterBlobSize / CryptoUtil.IvSize) + 1) * CryptoUtil.IvSize
            + CryptoUtil.HmacSize;

        /// <summary>容器头信息（不含条目区）。</summary>
        public class VaultHeader
        {
            public byte[] Salt = Array.Empty<byte>();       // 密码 KDF 盐（16B）
            public int KdfIterations;                       // PBKDF2 迭代次数
            public byte[] PwdCheck = Array.Empty<byte>();   // 密码校验器（32B）
            public byte[] WrapPwd = Array.Empty<byte>();    // 密码包装的主密钥（144B sealed）
            public byte[] AnsSalt = Array.Empty<byte>();    // 答案 KDF 盐（16B，未设置找回时为全 0）
            public byte[] AnsCheck = Array.Empty<byte>();   // 答案校验器（32B）
            public byte[] WrapAns = Array.Empty<byte>();    // 答案包装的主密钥（144B sealed）
            public string? Question;                        // 找回问题（null = 未设置）

            public bool HasRecovery => !string.IsNullOrEmpty(Question);
        }

        // ---------------- 读取 ----------------

        /// <summary>只读容器头（不读条目，用于读取找回问题等）。</summary>
        public static VaultHeader ReadHeader(string path)
        {
            using var fs = File.OpenRead(path);
            using var r = new BinaryReader(fs, Encoding.UTF8);
            return ReadHeader(r, out _);
        }

        /// <summary>读取完整容器内容（头部 + 条目表，不解密文件内容）。</summary>
        public static VaultBody ReadBody(string path)
        {
            using var fs = File.OpenRead(path);
            using var r = new BinaryReader(fs, Encoding.UTF8);
            var body = new VaultBody { Header = ReadHeader(r, out int version), Version = version };
            body.Entries = ReadEntries(r, fs, version);
            return body;
        }

        /// <summary>从流的当前位置读取容器头；version 输出实际版本号。</summary>
        public static VaultHeader ReadHeader(BinaryReader r, out int version)
        {
            if (Encoding.ASCII.GetString(r.ReadBytes(4)) != Magic)
                throw new InvalidDataException("不是有效的保险箱容器文件。");
            version = checked((int)r.ReadUInt32());
            if (version != VersionLegacy && version != Version)
                throw new InvalidDataException("容器版本不受支持，请使用对应版本的保险箱工具。");

            var h = new VaultHeader
            {
                Salt = r.ReadBytes(CryptoUtil.SaltSize),
                KdfIterations = checked((int)r.ReadUInt32()),
                PwdCheck = r.ReadBytes(CryptoUtil.HmacSize),
                WrapPwd = r.ReadBytes(WrapBlobSize),
                AnsSalt = r.ReadBytes(CryptoUtil.SaltSize),
                AnsCheck = r.ReadBytes(CryptoUtil.HmacSize),
                WrapAns = r.ReadBytes(WrapBlobSize),
            };

            int qlen = r.ReadInt32();
            if (qlen is < 0 or > 4096)
                throw new InvalidDataException("容器头部损坏。");
            h.Question = qlen == 0 ? null : Encoding.UTF8.GetString(r.ReadBytes(qlen));
            return h;
        }

        /// <summary>读取条目表（跳过文件密文，只记录偏移与长度）。</summary>
        public static List<VaultEntry> ReadEntries(BinaryReader r, FileStream fs, int version)
        {
            int count = r.ReadInt32();
            if (count is < 0 or > 1_000_000)
                throw new InvalidDataException("容器条目区损坏。");
            var list = new List<VaultEntry>(count);
            for (int i = 0; i < count; i++)
            {
                byte type = r.ReadByte();
                int nameLen = r.ReadInt32();
                if (nameLen is <= 0 or > 4096)
                    throw new InvalidDataException("容器条目损坏。");
                string name = Encoding.UTF8.GetString(r.ReadBytes(nameLen));

                long mtime = 0, ctime = 0;
                if (version >= Version)
                {
                    mtime = r.ReadInt64();
                    ctime = r.ReadInt64();
                }

                var e = new VaultEntry
                {
                    Name = name,
                    IsFile = type == 1,
                    Modified = FromTicks(mtime),
                    Created = FromTicks(ctime),
                };
                if (e.IsFile)
                {
                    long plainLen = r.ReadInt64();
                    if (plainLen < 0) throw new InvalidDataException("容器条目损坏。");
                    long sealedLen = SealedLength(plainLen);
                    e.PlainLength = plainLen;
                    e.DataOffset = fs.Position;
                    e.SealedLength = sealedLen;
                    fs.Seek(sealedLen, SeekOrigin.Current);
                }
                list.Add(e);
            }
            return list;
        }

        // ---------------- 写入 ----------------

        /// <summary>按当前布局写出容器头（与 ReadHeader 严格对称）。</summary>
        public static void WriteHeader(BinaryWriter w, VaultHeader h, int version = Version)
        {
            w.Write(Encoding.ASCII.GetBytes(Magic));
            w.Write((uint)version);
            w.Write(h.Salt);
            w.Write((uint)h.KdfIterations);
            w.Write(h.PwdCheck);
            w.Write(h.WrapPwd);
            w.Write(h.AnsSalt);
            w.Write(h.AnsCheck);
            w.Write(h.WrapAns);
            byte[] q = string.IsNullOrEmpty(h.Question) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(h.Question);
            w.Write(q.Length);
            w.Write(q);
        }

        /// <summary>写出条目元数据（不含文件密文）。</summary>
        public static void WriteEntryMeta(BinaryWriter w, VaultEntry e)
        {
            w.Write((byte)(e.IsFile ? 1 : 2));
            // 必须写 UTF-8 字节数而非字符数（中文名占多个字节），读取端按字节数读取
            byte[] nameBytes = Encoding.UTF8.GetBytes(e.Name);
            w.Write(nameBytes.Length);
            w.Write(nameBytes);
            // 时间戳按 UTC ticks 存储（未知时间写 0，避免 MinValue 转换溢出）
            w.Write(e.Modified == DateTime.MinValue ? 0L : e.Modified.ToUniversalTime().Ticks);
            w.Write(e.Created == DateTime.MinValue ? 0L : e.Created.ToUniversalTime().Ticks);
            if (e.IsFile) w.Write(e.PlainLength);
        }

        /// <summary>写出一个空容器（头 + 条目数 0）。用于创建新保险箱。</summary>
        public static void WriteNew(string path, VaultHeader h)
        {
            string tmp = path + ".tmp";
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            using (var w = new BinaryWriter(fs, Encoding.UTF8))
            {
                WriteHeader(w, h);
                w.Write(0); // 条目数
                w.Flush();
                fs.Flush(true);
            }
            CommitTemp(tmp, path);
        }

        /// <summary>
        /// 仅重写容器头（条目区原样复制，保留原版本号）。
        /// 用于修改密码 / 设置找回等只动头部的操作。
        /// </summary>
        public static void RewriteHeader(string path, VaultHeader h)
        {
            string tmp = path + ".tmp";
            using (var src = File.OpenRead(path))
            using (var r = new BinaryReader(src, Encoding.UTF8))
            using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            using (var w = new BinaryWriter(dst, Encoding.UTF8))
            {
                ReadHeader(r, out int version);   // 跳过原头部（内容以参数 h 为准），保留原版本号
                WriteHeader(w, h, version);
                var buf = new byte[1 << 20];
                int n;
                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                    w.Write(buf, 0, n);
                w.Flush();
                dst.Flush(true);
            }
            CommitTemp(tmp, path);
        }

        /// <summary>
        /// 把临时文件原子替换为目标文件：优先 File.Replace（保留 .bak 备份），
        /// 失败则退化为删除+移动。目标不存在时直接移动（用于新建）。
        /// </summary>
        internal static void CommitTemp(string tmp, string path)
        {
            if (File.Exists(path))
            {
                string bak = path + ".bak";
                try
                {
                    File.Replace(tmp, path, bak);
                    return;
                }
                catch
                {
                    try { File.Delete(bak); } catch { }
                    File.Delete(path);
                }
            }
            File.Move(tmp, path);
        }

        // ---------------- 辅助 ----------------

        /// <summary>文件 sealed 数据总长度（IV + 密文 + MAC）。</summary>
        public static long SealedLength(long plainLen)
            => CryptoUtil.IvSize + ((plainLen / CryptoUtil.IvSize) + 1) * CryptoUtil.IvSize + CryptoUtil.HmacSize;

        /// <summary>UTC ticks → 本地时间（0 表示未知）。</summary>
        private static DateTime FromTicks(long ticks)
            => ticks <= 0 ? DateTime.MinValue : new DateTime(ticks, DateTimeKind.Utc).ToLocalTime();
    }
}
