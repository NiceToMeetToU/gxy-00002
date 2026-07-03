using System;

namespace GMEncryptTool
{
    class TestAllAlgorithms
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== 国密算法测试程序 ===\n");

            TestSM2();
            Console.WriteLine();

            TestSM3();
            Console.WriteLine();

            TestSM4();
            Console.WriteLine();

            TestSM9();
            Console.WriteLine();

            TestZUC();

            Console.WriteLine("\n=== 所有测试完成 ===");
        }

        static void TestSM2()
        {
            Console.WriteLine("--- SM2 测试 ---");
            try
            {
                var keyPair = SM2Utils.GenerateKeyPair();
                Console.WriteLine($"公钥: {keyPair.PublicKey.Substring(0, 40)}...");
                Console.WriteLine($"私钥: {keyPair.PrivateKey.Substring(0, 40)}...");

                string plainText = "Hello, SM2!";
                string encrypted = SM2Utils.Encrypt(plainText, keyPair.PublicKey);
                Console.WriteLine($"加密结果: {encrypted.Substring(0, 40)}...");

                string decrypted = SM2Utils.Decrypt(encrypted, keyPair.PrivateKey);
                Console.WriteLine($"解密结果: {decrypted}");
                Console.WriteLine($"加密解密验证: {(decrypted == plainText ? "通过" : "失败")}");

                string signature = SM2Utils.Sign(plainText, keyPair.PrivateKey);
                bool verified = SM2Utils.Verify(plainText, signature, keyPair.PublicKey);
                Console.WriteLine($"签名验证: {(verified ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM2测试失败: {ex.Message}");
            }
        }

        static void TestSM3()
        {
            Console.WriteLine("--- SM3 测试 ---");
            try
            {
                string plainText = "Hello, SM3!";
                string hash = SM3Utils.Hash(plainText);
                Console.WriteLine($"输入: {plainText}");
                Console.WriteLine($"SM3哈希值: {hash}");
                Console.WriteLine($"哈希长度: {hash.Length}");

                bool verified = SM3Utils.Verify(plainText, hash);
                Console.WriteLine($"哈希验证: {(verified ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM3测试失败: {ex.Message}");
            }
        }

        static void TestSM4()
        {
            Console.WriteLine("--- SM4 测试 ---");
            try
            {
                string key = SM4Utils.GenerateKey();
                string iv = SM4Utils.GenerateIV();
                Console.WriteLine($"密钥: {key}");
                Console.WriteLine($"IV: {iv}");

                string plainText = "Hello, SM4!";

                string ecbEncrypted = SM4Utils.EncryptECB(plainText, key);
                string ecbDecrypted = SM4Utils.DecryptECB(ecbEncrypted, key);
                Console.WriteLine($"ECB加密: {ecbEncrypted}");
                Console.WriteLine($"ECB解密: {ecbDecrypted}");
                Console.WriteLine($"ECB验证: {(ecbDecrypted == plainText ? "通过" : "失败")}");

                string cbcEncrypted = SM4Utils.EncryptCBC(plainText, key, iv);
                string cbcDecrypted = SM4Utils.DecryptCBC(cbcEncrypted, key, iv);
                Console.WriteLine($"CBC加密: {cbcEncrypted}");
                Console.WriteLine($"CBC解密: {cbcDecrypted}");
                Console.WriteLine($"CBC验证: {(cbcDecrypted == plainText ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM4测试失败: {ex.Message}");
            }
        }

        static void TestSM9()
        {
            Console.WriteLine("--- SM9 测试 ---");
            try
            {
                var keyPair = SM9Utils.GenerateMasterKeyPair();
                Console.WriteLine($"主公钥: {keyPair.MasterPublicKey.Substring(0, 40)}...");
                Console.WriteLine($"主私钥: {keyPair.MasterPrivateKey.Substring(0, 40)}...");

                string identity = "user@example.com";
                string publicKey = SM9Utils.DerivePublicKey(keyPair.MasterPublicKey, identity);
                Console.WriteLine($"派生公钥: {publicKey.Substring(0, 40)}...");

                string plainText = "Hello, SM9!";
                string encrypted = SM9Utils.Encrypt(plainText, publicKey);
                string decrypted = SM9Utils.Decrypt(encrypted, keyPair.MasterPrivateKey, identity);
                Console.WriteLine($"解密结果: {decrypted}");
                Console.WriteLine($"验证: {(decrypted == plainText ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM9测试失败: {ex.Message}");
            }
        }

        static void TestZUC()
        {
            Console.WriteLine("--- ZUC 测试 ---");
            try
            {
                string key = ZUCUtils.GenerateKey();
                string iv = ZUCUtils.GenerateIV();
                Console.WriteLine($"密钥: {key}");
                Console.WriteLine($"IV: {iv}");

                string plainText = "Hello, ZUC!";
                string encrypted = ZUCUtils.Encrypt(plainText, key, iv);
                string decrypted = ZUCUtils.Decrypt(encrypted, key, iv);
                Console.WriteLine($"加密: {encrypted}");
                Console.WriteLine($"解密: {decrypted}");
                Console.WriteLine($"验证: {(decrypted == plainText ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ZUC测试失败: {ex.Message}");
            }
        }
    }
}