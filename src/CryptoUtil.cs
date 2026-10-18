using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecretVault
{
    /// <summary>
    /// 加解密工具集 —— 整个工具的唯一加密入口，所有加密操作都经过这里。
    ///
    /// 设计要点（对应需求）：
    ///   1) AES-256 对称加密：CBC 模式 + PKCS7 填充，每次加密使用随机 16 字节 IV。
    ///   2) 密钥派生：PBKDF2-HMAC-SHA256，盐值 16 字节，默认迭代 200,000 次（写入容器头）。
    ///   3) 完整性：Encrypt-then-MAC —— 先加密、后对 (IV || 密文) 计算 HMAC-SHA256，
    ///      解密前先验 MAC，被篡改/损坏的数据直接拒绝。
    ///   4) 包装密钥（Wrap Key）= 64 字节：前 32 字节作 AES-256 密钥，后 32 字节作 HMAC 密钥。
    ///
    /// 密封数据（Sealed）布局：IV(16) || AES-CBC(明文) || HMAC-SHA256(IV||密文)(32)
    ///
    /// 注意：以下三处是针对 .NET Framework 运行时行为（不是编译器）的必要处理，
    /// 与语言版本无关，在 .NET Core/.NET 5+ 上则不需要：
    ///   a) CryptoStream 在 .NET Framework 上 Dispose 不会自动刷出 PKCS7 末尾补齐块，
    ///      必须显式 FlushFinalBlock()；
    ///   b) HashAlgorithm.TransformFinalBlock(空输入) 的返回值不可用（为空数组），
    ///      需改读 Hash 属性；
    ///   c) CryptoStream 释放时会关闭底层流、读模式会越过边界预读，
    ///      因此解密路径使用 BoundedReadStream 限界并对齐流位置。
    /// </summary>
    public static class CryptoUtil
    {
        public const int SaltSize = 16;                  // PBKDF2 盐长度
        public const int IvSize = 16;                    // AES 分组 / IV 长度
        public const int AesKeySize = 32;                // AES-256 密钥长度
        public const int HmacKeySize = 32;               // HMAC-SHA256 密钥长度
        public const int HmacSize = 32;                  // HMAC 输出长度
        public const int WrapKeySize = AesKeySize + HmacKeySize; // 包装密钥总长 64
        public const int MasterBlobSize = 80;            // 被包装的主密钥块：64(主密钥)+16(魔数)
        public const int DefaultKdfIterations = 200_000; // PBKDF2 迭代次数（约 0.2~0.5 秒）

        /// <summary>主密钥块末尾的校验魔数（16 字节），用于确认解包成功。</summary>
        public static readonly byte[] MasterMagic = Encoding.ASCII.GetBytes("VLT-MASTER-CHECK");

        // 密码 / 找回答案的 HMAC 校验标签
        private static readonly byte[] PwdCheckTag = Encoding.ASCII.GetBytes("VLT-PWD-CHECK");
        private static readonly byte[] AnsCheckTag = Encoding.ASCII.GetBytes("VLT-ANS-CHECK");

        /// <summary>生成随机盐。</summary>
        public static byte[] NewSalt()
        {
            var s = new byte[SaltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(s);
            return s;
        }

        /// <summary>生成随机 IV。</summary>
        public static byte[] NewIv()
        {
            var iv = new byte[IvSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(iv);
            return iv;
        }

        /// <summary>生成随机主密钥（64 字节：AES-256 密钥 32B + HMAC-SHA256 密钥 32B）。</summary>
        public static byte[] NewMasterKey()
        {
            var k = new byte[WrapKeySize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(k);
            return k;
        }

        /// <summary>PBKDF2-HMAC-SHA256 派生指定长度的密钥（需求：密钥由用户密码通过 PBKDF2 派生）。</summary>
        public static byte[] DeriveKey(string password, byte[] salt, int iterations, int length)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("密码不能为空。");
            using var p = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return p.GetBytes(length);
        }

        /// <summary>由口令派生 64 字节包装密钥（前 32 = AES 密钥，后 32 = HMAC 密钥）。</summary>
        public static byte[] DeriveWrapKey(string password, byte[] salt, int iterations)
            => DeriveKey(password, salt, iterations, WrapKeySize);

        /// <summary>恒定时间比较两个字节数组，避免时序侧信道。</summary>
        public static bool FixedTimeEquals(byte[]? a, byte[]? b)
        {
            if (a is null || b is null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>截取字节数组片段（.NET Framework 无 System.Range，用 Buffer.BlockCopy 实现）。</summary>
        public static byte[] Slice(byte[] src, int offset, int count)
        {
            var r = new byte[count];
            Buffer.BlockCopy(src, offset, r, 0, count);
            return r;
        }

        /// <summary>计算凭证校验器：HMAC-SHA256(包装密钥的 HMAC 半段, 标签)。用于快速判断口令是否正确。</summary>
        public static byte[] ComputeCheck(byte[] wrapKey, bool isPassword)
            => Hmac(Slice(wrapKey, AesKeySize, HmacKeySize), isPassword ? PwdCheckTag : AnsCheckTag);

        /// <summary>校验主密钥块末尾魔数（确认解包出的主密钥正确）。</summary>
        public static bool HasMasterMagic(byte[]? masterBlob)
        {
            if (masterBlob is null || masterBlob.Length != MasterBlobSize) return false;
            for (int i = 0; i < MasterMagic.Length; i++)
                if (masterBlob[WrapKeySize + i] != MasterMagic[i]) return false;
            return true;
        }

        /// <summary>拼接两个字节数组。</summary>
        public static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        /// <summary>清零密钥材料（尽力而为，减少密钥在内存中的滞留时间）。</summary>
        public static void Wipe(byte[]? buf)
        {
            if (buf != null) Array.Clear(buf, 0, buf.Length);
        }

        /// <summary>
        /// HMAC-SHA256 串联计算：对 parts 依次喂入后取最终哈希。
        /// 注意：.NET Framework 上 TransformFinalBlock(空输入) 的返回值不可用（为空数组），
        /// 必须先调用它收尾，再显式读取 Hash 属性。
        /// </summary>
        public static byte[] Hmac(byte[] key, params byte[][] parts)
        {
            using var h = new HMACSHA256(key);
            foreach (var p in parts) h.TransformBlock(p, 0, p.Length, null, 0);
            h.TransformFinalBlock(new byte[0], 0, 0); // 收尾状态
            return h.Hash;                            // 真正的 32 字节 HMAC 结果
        }

        /// <summary>
        /// 密封（加密 + 完整性校验）整个字节数组，返回 IV||密文||MAC。
        /// wrapKey：前 32 字节 AES 密钥，后 32 字节 HMAC 密钥。
        /// </summary>
        public static byte[] SealBytes(byte[] wrapKey, byte[] plain)
        {
            using var src = new MemoryStream(plain);
            using var dst = new MemoryStream();
            SealStream(src, dst, wrapKey, plain.Length);
            return dst.ToArray();
        }

        /// <summary>解封字节数组；MAC 校验失败抛 CryptographicException。</summary>
        public static byte[] OpenBytes(byte[] wrapKey, byte[] sealedBlob, int plainLen)
        {
            using var src = new MemoryStream(sealedBlob);
            using var dst = new MemoryStream();
            OpenStream(src, dst, wrapKey, plainLen);
            return dst.ToArray();
        }

        /// <summary>
        /// 流式密封：把明文流加密写入目标流（支持大文件，不整体读入内存）。
        /// 写入布局：IV(16) || 密文 || HMAC(IV||密文)(32)。返回写入总字节数。
        /// 调用前源流应已定位到明文起点。
        /// </summary>
        public static long SealStream(Stream src, Stream dst, byte[] wrapKey, long plainLen)
        {
            var iv = NewIv();
            var aesKey = Slice(wrapKey, 0, AesKeySize);
            var macKey = Slice(wrapKey, AesKeySize, HmacKeySize);
            using var aes = new AesCryptoServiceProvider();
            using var hmac = new HMACSHA256(macKey);
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = iv;

            // 1) 写出 IV，并把它计入 MAC
            dst.Write(iv, 0, iv.Length);
            hmac.TransformBlock(iv, 0, iv.Length, null, 0);

            // 2) 明文 → AES 加密 → HmacTeeStream（密文边写边计入 MAC）→ dst
            //    Encrypt-then-MAC：MAC 覆盖的是密文，而非明文。
            using (var tee = new HmacTeeStream(hmac, dst))
            using (var enc = new CryptoStream(tee, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                Copy(src, enc, plainLen);
                // .NET Framework 的 CryptoStream 在 Dispose 时不会自动刷出
                // 末尾的 PKCS7 补齐块，必须显式调用 FlushFinalBlock。
                enc.FlushFinalBlock();
            }

            // 3) 收尾 MAC 并写出（TransformFinalBlock 返回值不可用，读 Hash 属性）
            hmac.TransformFinalBlock(new byte[0], 0, 0);
            var mac = hmac.Hash;
            dst.Write(mac, 0, mac.Length);

            long ctLen = ((plainLen / IvSize) + 1) * IvSize; // CBC+PKCS7：密文 = 整分组数
            return IvSize + ctLen + HmacSize;
        }

        /// <summary>
        /// 流式解封：从源流读取 sealed 数据并解密到目标流。
        /// 两遍处理：第一遍只算 MAC（不碰明文），校验通过后才真正解密，
        /// 保证被篡改的数据绝不会产生任何明文输出。
        /// 调用前源流应已定位到 sealed 起点；plainLen 为明文长度。
        /// 通过 BoundedReadStream 把读取严格限制在本封块内：
        ///  - CryptoStream 读缓冲区不会越过封块边界吞掉下一个条目的数据；
        ///  - CryptoStream 释放时关闭的是边界流，源流保持打开供后续条目使用。
        /// </summary>
        public static void OpenStream(Stream src, Stream dst, byte[] wrapKey, long plainLen)
        {
            long ctLen = ((plainLen / IvSize) + 1) * IvSize;
            long blobLen = IvSize + ctLen + HmacSize;
            var aesKey = Slice(wrapKey, 0, AesKeySize);
            var macKey = Slice(wrapKey, AesKeySize, HmacKeySize);
            using var aes = new AesCryptoServiceProvider();
            using var hmac = new HMACSHA256(macKey);
            using var bounded = new BoundedReadStream(src, blobLen);
            {
                // —— 第一遍：读取 IV+密文计算 MAC（不输出任何明文）——
                var iv = ReadExact(bounded, IvSize);
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                var buf = new byte[1 << 20];
                long remain = ctLen;
                while (remain > 0)
                {
                    int n = bounded.Read(buf, 0, (int)Math.Min(buf.Length, remain));
                    if (n <= 0) throw new EndOfStreamException("密封数据被截断。");
                    remain -= n;
                    hmac.TransformBlock(buf, 0, n, null, 0);
                }
                var expect = ReadExact(bounded, HmacSize);
                hmac.TransformFinalBlock(new byte[0], 0, 0);
                var actual = hmac.Hash;
                if (!FixedTimeEquals(expect, actual))
                    throw new CryptographicException("完整性校验失败：数据可能被篡改或已损坏。");
                Wipe(buf);

                // —— 第二遍：回到密文起点，真正解密 ——
                bounded.Seek(-(ctLen + HmacSize), SeekOrigin.Current);
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = aesKey;
                aes.IV = iv;
                // 解密遍只暴露“密文”本身：否则 CryptoStream 会继续把后面的 MAC 字节
                // 当作多余密文读取，导致末尾填充校验失败。
                using var ctOnly = new BoundedReadStream(bounded, ctLen);
                using var dec = new CryptoStream(ctOnly, aes.CreateDecryptor(), CryptoStreamMode.Read);
                Copy(dec, dst, plainLen);

                // 解密完成后把外层流对齐到封块末尾（解密器可能未消费末尾的填充块），
                // 保证下一个条目的读取位置正确。
                bounded.Seek(blobLen, SeekOrigin.Begin);
            }
        }

        /// <summary>把源流中恰好 count 字节复制到目标流（不足则抛异常）。</summary>
        public static void Copy(Stream src, Stream dst, long count)
        {
            var buf = new byte[1 << 20];
            while (count > 0)
            {
                int n = src.Read(buf, 0, (int)Math.Min(buf.Length, count));
                if (n <= 0) throw new EndOfStreamException("数据不足。");
                dst.Write(buf, 0, n);
                count -= n;
            }
        }

        /// <summary>读取恰好 n 字节（不足则抛异常）。</summary>
        private static byte[] ReadExact(Stream s, int n)
        {
            var buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = s.Read(buf, off, n - off);
                if (r <= 0) throw new EndOfStreamException("数据被截断。");
                off += r;
            }
            return buf;
        }

        /// <summary>
        /// 只读的“封块边界流”：把读取/寻址范围限制在源流接下来的 length 字节内，
        /// 防止 CryptoStream 读缓冲区越过封块边界吞掉下一个条目的数据。
        /// Close/Dispose 不关闭内层流（由调用方管理）。
        /// </summary>
        private sealed class BoundedReadStream : Stream
        {
            private readonly Stream _inner;
            private readonly long _length;
            private long _position;

            public BoundedReadStream(Stream inner, long length)
            {
                _inner = inner;
                _length = length;
                _position = 0;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_position >= _length) return 0;
                int n = _inner.Read(buffer, offset, (int)Math.Min(count, _length - _position));
                _position += n;
                return n;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                long newPos = origin switch
                {
                    SeekOrigin.Current => _position + offset,
                    SeekOrigin.Begin => offset,
                    _ => _length + offset,
                };
                if (newPos < 0 || newPos > _length) throw new IOException("封块内越界寻址。");
                _inner.Seek(newPos - _position, SeekOrigin.Current);
                _position = newPos;
                return newPos;
            }

            public override void Flush() { }
            public override bool CanRead => true;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length => _length;
            public override long Position
            {
                get => _position;
                set => Seek(value, SeekOrigin.Begin);
            }
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }

        /// <summary>
        /// 透传流：写入的数据同时喂给 HMAC 再转给内层流（用于对密文边写边算 MAC）。
        /// 注意：Dispose 不关闭内层流，由调用方管理。
        /// </summary>
        private sealed class HmacTeeStream : Stream
        {
            private readonly HashAlgorithm _hmac;
            private readonly Stream _inner;

            public HmacTeeStream(HashAlgorithm hmac, Stream inner)
            {
                _hmac = hmac;
                _inner = inner;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _hmac.TransformBlock(buffer, offset, count, null, 0);
                _inner.Write(buffer, offset, count);
            }

            public override void Flush() => _inner.Flush();
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => _inner.Length;
            public override long Position
            {
                get => _inner.Position;
                set => throw new NotSupportedException();
            }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
