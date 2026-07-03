using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace GMEncryptTool
{
    public static class SM2Utils
    {
        private static readonly X9ECParameters _x9 = GMNamedCurves.GetByName("SM2P256V1");
        private const int RS_LEN = 32;

        public static (string PublicKey, string PrivateKey) GenerateKeyPair()
        {
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(new ECDomainParameters(_x9), new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            byte[] publicKey = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(false);
            byte[] privateKey = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();

            return (Hex.ToHexString(publicKey).ToUpper(), Hex.ToHexString(privateKey).ToUpper());
        }

        public static string Encrypt(string plainText, string publicKeyHex)
        {
            byte[] publicKeyBytes = Hex.Decode(publicKeyHex);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
                _x9.Curve.DecodePoint(publicKeyBytes),
                new ECDomainParameters(_x9));

            SM2Engine engine = new SM2Engine();
            engine.Init(true, new ParametersWithRandom(publicKey, new SecureRandom()));

            byte[] encryptedBytes = engine.ProcessBlock(plainBytes, 0, plainBytes.Length);
            return Hex.ToHexString(encryptedBytes).ToUpper();
        }

        public static string Decrypt(string cipherTextHex, string privateKeyHex)
        {
            byte[] privateKeyBytes = Hex.Decode(privateKeyHex);
            byte[] cipherBytes = Hex.Decode(cipherTextHex);

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(
                new BigInteger(1, privateKeyBytes),
                new ECDomainParameters(_x9));

            SM2Engine engine = new SM2Engine();
            engine.Init(false, privateKey);

            byte[] decryptedBytes = engine.ProcessBlock(cipherBytes, 0, cipherBytes.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public static string Sign(string data, string privateKeyHex, string userId = "1234567812345678")
        {
            byte[] privateKeyBytes = Hex.Decode(privateKeyHex);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] userIdBytes = Encoding.UTF8.GetBytes(userId);

            SM2Signer signer = new SM2Signer(new SM3Digest());
            ICipherParameters parameters = new ParametersWithRandom(
                new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), new ECDomainParameters(_x9)));

            if (userIdBytes != null && userIdBytes.Length > 0)
            {
                parameters = new ParametersWithID(parameters, userIdBytes);
            }

            signer.Init(true, parameters);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            byte[] signatureDer = signer.GenerateSignature();
            byte[] signature = RsAsn1ToPlainByteArray(signatureDer);

            return Hex.ToHexString(signature).ToUpper();
        }

        public static bool Verify(string data, string signatureHex, string publicKeyHex, string userId = "1234567812345678")
        {
            byte[] publicKeyBytes = Hex.Decode(publicKeyHex);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = Hex.Decode(signatureHex);
            byte[] userIdBytes = Encoding.UTF8.GetBytes(userId);

            byte[] signatureDer = RsAsn1FromPlainByteArray(signatureBytes);

            SM2Signer signer = new SM2Signer(new SM3Digest());
            ICipherParameters parameters = new ECPublicKeyParameters(
                _x9.Curve.DecodePoint(publicKeyBytes),
                new ECDomainParameters(_x9));

            if (userIdBytes != null && userIdBytes.Length > 0)
            {
                parameters = new ParametersWithID(parameters, userIdBytes);
            }

            signer.Init(false, parameters);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            return signer.VerifySignature(signatureDer);
        }

        private static byte[] RsAsn1ToPlainByteArray(byte[] signDer)
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(signDer);
            byte[] r = BigIntToFixedLengthBytes(DerInteger.GetInstance(seq[0]).Value);
            byte[] s = BigIntToFixedLengthBytes(DerInteger.GetInstance(seq[1]).Value);
            byte[] result = new byte[RS_LEN * 2];
            Buffer.BlockCopy(r, 0, result, 0, r.Length);
            Buffer.BlockCopy(s, 0, result, RS_LEN, s.Length);
            return result;
        }

        private static byte[] RsAsn1FromPlainByteArray(byte[] sign)
        {
            if (sign.Length != RS_LEN * 2)
                throw new ArgumentException("Signature length must be 64 bytes");

            BigInteger r = new BigInteger(1, Arrays.CopyOfRange(sign, 0, RS_LEN));
            BigInteger s = new BigInteger(1, Arrays.CopyOfRange(sign, RS_LEN, RS_LEN * 2));

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerInteger(r));
            v.Add(new DerInteger(s));

            try
            {
                return new DerSequence(v).GetEncoded("DER");
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        private static byte[] BigIntToFixedLengthBytes(BigInteger rOrS)
        {
            byte[] rs = rOrS.ToByteArray();
            if (rs.Length == RS_LEN) return rs;
            if (rs.Length == RS_LEN + 1 && rs[0] == 0)
                return Arrays.CopyOfRange(rs, 1, RS_LEN + 1);
            if (rs.Length < RS_LEN)
            {
                byte[] result = new byte[RS_LEN];
                Arrays.Fill(result, (byte)0);
                Buffer.BlockCopy(rs, 0, result, RS_LEN - rs.Length, rs.Length);
                return result;
            }
            throw new ArgumentException("Invalid RS value");
        }
    }
}