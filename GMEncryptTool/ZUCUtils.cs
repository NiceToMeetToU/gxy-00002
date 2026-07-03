using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;
using System.Text;

namespace GMEncryptTool
{
    public static class ZUCUtils
    {
        private const int LFSR_LENGTH = 16;
        private const int KEY_LENGTH = 16;
        private const int IV_LENGTH = 16;

        public static string GenerateKey()
        {
            byte[] key = new byte[KEY_LENGTH];
            RandomNumberGenerator.Fill(key);
            return Hex.ToHexString(key).ToUpper();
        }

        public static string GenerateIV()
        {
            byte[] iv = new byte[IV_LENGTH];
            RandomNumberGenerator.Fill(iv);
            return Hex.ToHexString(iv).ToUpper();
        }

        public static string Encrypt(string plainText, string keyHex, string ivHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] iv = Hex.Decode(ivHex);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keystream = GenerateKeystream(key, iv, plainBytes.Length);
            byte[] cipherBytes = Xor(plainBytes, keystream);

            return Hex.ToHexString(cipherBytes).ToUpper();
        }

        public static string Decrypt(string cipherTextHex, string keyHex, string ivHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] iv = Hex.Decode(ivHex);
            byte[] cipherBytes = Hex.Decode(cipherTextHex);

            byte[] keystream = GenerateKeystream(key, iv, cipherBytes.Length);
            byte[] plainBytes = Xor(cipherBytes, keystream);

            return Encoding.UTF8.GetString(plainBytes);
        }

        private static byte[] GenerateKeystream(byte[] key, byte[] iv, int length)
        {
            uint[] lfsr = InitializeLFSR(key, iv);
            byte[] keystream = new byte[length];

            for (int i = 0; i < 32; i++)
            {
                GenerateNextState(ref lfsr);
            }

            for (int i = 0; i < length; i++)
            {
                GenerateNextState(ref lfsr);
                keystream[i] = (byte)(lfsr[0] ^ lfsr[1] ^ lfsr[2] ^ lfsr[3]);
            }

            return keystream;
        }

        private static uint[] InitializeLFSR(byte[] key, byte[] iv)
        {
            uint[] lfsr = new uint[LFSR_LENGTH];

            for (int i = 0; i < 4; i++)
            {
                lfsr[i] = (uint)((key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3]);
                lfsr[i + 4] = (uint)((iv[i * 4] << 24) | (iv[i * 4 + 1] << 16) | (iv[i * 4 + 2] << 8) | iv[i * 4 + 3]);
                lfsr[i + 8] = lfsr[i] ^ lfsr[i + 4];
                lfsr[i + 12] = lfsr[i + 4] ^ lfsr[i + 8];
            }

            return lfsr;
        }

        private static void GenerateNextState(ref uint[] lfsr)
        {
            uint s0 = lfsr[0];
            uint s15 = lfsr[15];

            uint f = s0 ^ s15;
            f = (f << 1) | ((f >> 31) & 1);
            f ^= (s0 >> 1) & 1;

            for (int i = 0; i < LFSR_LENGTH - 1; i++)
            {
                lfsr[i] = lfsr[i + 1];
            }

            lfsr[15] = f;
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
    }
}