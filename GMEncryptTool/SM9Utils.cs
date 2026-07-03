using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace GMEncryptTool
{
    public static class SM9Utils
    {
        private static readonly X9ECParameters _ecParameters = GMNamedCurves.GetByName("SM2P256V1");
        private static readonly ECDomainParameters _domainParams = new ECDomainParameters(_ecParameters);

        public static (string MasterPublicKey, string MasterPrivateKey) GenerateMasterKeyPair()
        {
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(_domainParams, new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            byte[] publicKey = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(false);
            byte[] privateKey = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();

            return (Hex.ToHexString(publicKey).ToUpper(), Hex.ToHexString(privateKey).ToUpper());
        }

        public static string DerivePublicKey(string masterPublicKeyHex, string identity)
        {
            byte[] masterPublicKeyBytes = Hex.Decode(masterPublicKeyHex);
            ECPublicKeyParameters masterPublicKey = new ECPublicKeyParameters(
                _ecParameters.Curve.DecodePoint(masterPublicKeyBytes),
                _domainParams);

            byte[] identityBytes = Encoding.UTF8.GetBytes(identity);
            byte[] hash = ComputeSM9Hash(identityBytes);

            BigInteger hashInt = new BigInteger(1, hash);
            hashInt = hashInt.Mod(_ecParameters.N);

            var derivedPoint = masterPublicKey.Q.Multiply(hashInt).Normalize();

            return Hex.ToHexString(derivedPoint.GetEncoded(false)).ToUpper();
        }

        public static string Encrypt(string plainText, string publicKeyHex)
        {
            byte[] publicKeyBytes = Hex.Decode(publicKeyHex);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
                _ecParameters.Curve.DecodePoint(publicKeyBytes),
                _domainParams);

            SecureRandom random = new SecureRandom();
            BigInteger k = new BigInteger(_ecParameters.N.BitLength - 1, random);
            k = k.Mod(_ecParameters.N);
            if (k.SignValue <= 0)
                k = k.Add(BigInteger.One);

            var c1 = _ecParameters.G.Multiply(k).Normalize();
            var c2Point = publicKey.Q.Multiply(k).Normalize();

            byte[] c2Bytes = c2Point.GetEncoded(false);
            byte[] c2 = new byte[plainBytes.Length];
            for (int i = 0; i < plainBytes.Length; i++)
            {
                c2[i] = (byte)(plainBytes[i] ^ c2Bytes[i % c2Bytes.Length]);
            }

            byte[] c1Bytes = c1.GetEncoded(false);
            byte[] combined = new byte[c1Bytes.Length + c2.Length];
            Buffer.BlockCopy(c1Bytes, 0, combined, 0, c1Bytes.Length);
            Buffer.BlockCopy(c2, 0, combined, c1Bytes.Length, c2.Length);

            return Hex.ToHexString(combined).ToUpper();
        }

        public static string Decrypt(string cipherTextHex, string privateKeyHex, string identity)
        {
            byte[] cipherBytes = Hex.Decode(cipherTextHex);
            byte[] privateKeyBytes = Hex.Decode(privateKeyHex);

            BigInteger masterPrivateKey = new BigInteger(1, privateKeyBytes);
            byte[] identityBytes = Encoding.UTF8.GetBytes(identity);
            byte[] hash = ComputeSM9Hash(identityBytes);
            BigInteger hashInt = new BigInteger(1, hash);
            hashInt = hashInt.Mod(_ecParameters.N);

            BigInteger dId = masterPrivateKey.Multiply(hashInt).Mod(_ecParameters.N);

            int c1Length = 65;
            if (cipherBytes.Length <= c1Length)
                throw new ArgumentException("Invalid cipher text length");

            byte[] c1Bytes = new byte[c1Length];
            byte[] c2 = new byte[cipherBytes.Length - c1Length];
            Buffer.BlockCopy(cipherBytes, 0, c1Bytes, 0, c1Length);
            Buffer.BlockCopy(cipherBytes, c1Length, c2, 0, c2.Length);

            var c1 = _ecParameters.Curve.DecodePoint(c1Bytes);
            var s = c1.Multiply(dId).Normalize();

            byte[] sBytes = s.GetEncoded(false);
            byte[] plainBytes = new byte[c2.Length];
            for (int i = 0; i < c2.Length; i++)
            {
                plainBytes[i] = (byte)(c2[i] ^ sBytes[i % sBytes.Length]);
            }

            return Encoding.UTF8.GetString(plainBytes);
        }

        private static byte[] ComputeSM9Hash(byte[] data)
        {
            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
    }
}