using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace GMEncryptTool
{
    public static class SM4Utils
    {
        private const int KeySize = 16;
        private const int BlockSize = 16;

        public static string GenerateKey()
        {
            byte[] key = new byte[KeySize];
            SecureRandom random = new SecureRandom();
            random.NextBytes(key);
            return Hex.ToHexString(key).ToUpper();
        }

        public static string GenerateIV()
        {
            byte[] iv = new byte[BlockSize];
            SecureRandom random = new SecureRandom();
            random.NextBytes(iv);
            return Hex.ToHexString(iv).ToUpper();
        }

        public static string EncryptECB(string plainText, string keyHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new EcbBlockCipher(new SM4Engine()));
            cipher.Init(true, new KeyParameter(key));

            byte[] encryptedBytes = ProcessCipher(cipher, plainBytes);
            return Hex.ToHexString(encryptedBytes).ToUpper();
        }

        public static string DecryptECB(string cipherTextHex, string keyHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] cipherBytes = Hex.Decode(cipherTextHex);

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new EcbBlockCipher(new SM4Engine()));
            cipher.Init(false, new KeyParameter(key));

            byte[] decryptedBytes = ProcessCipher(cipher, cipherBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public static string EncryptCBC(string plainText, string keyHex, string ivHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] iv = Hex.Decode(ivHex);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] encryptedBytes = ProcessCipher(cipher, plainBytes);
            return Hex.ToHexString(encryptedBytes).ToUpper();
        }

        public static string DecryptCBC(string cipherTextHex, string keyHex, string ivHex)
        {
            byte[] key = Hex.Decode(keyHex);
            byte[] iv = Hex.Decode(ivHex);
            byte[] cipherBytes = Hex.Decode(cipherTextHex);

            IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] decryptedBytes = ProcessCipher(cipher, cipherBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        private static byte[] ProcessCipher(IBufferedCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);

            if (len != output.Length)
            {
                byte[] temp = new byte[len];
                Array.Copy(output, 0, temp, 0, len);
                output = temp;
            }

            return output;
        }
    }
}