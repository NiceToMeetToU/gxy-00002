using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace GMEncryptTool
{
    public static class SM3Utils
    {
        public static string Hash(string plainText)
        {
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            return Hash(data);
        }

        public static string Hash(byte[] data)
        {
            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return Hex.ToHexString(result).ToUpper();
        }

        public static bool Verify(string plainText, string expectedHash)
        {
            string actualHash = Hash(plainText);
            return actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        public static bool Verify(byte[] data, string expectedHash)
        {
            string actualHash = Hash(data);
            return actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }
    }
}