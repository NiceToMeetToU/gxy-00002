using System;

namespace GMEncryptTool
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("============================================");
            Console.WriteLine("          国密算法工具 (SM2/SM3/SM4/SM9/ZUC)");
            Console.WriteLine("============================================");
            Console.WriteLine();

            while (true)
            {
                ShowMainMenu();
                string choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1":
                        HandleSM2();
                        break;
                    case "2":
                        HandleSM3();
                        break;
                    case "3":
                        HandleSM4();
                        break;
                    case "4":
                        HandleSM9();
                        break;
                    case "5":
                        HandleZUC();
                        break;
                    case "0":
                        Console.WriteLine("退出程序...");
                        return;
                    default:
                        Console.WriteLine("无效选择，请重新输入");
                        break;
                }

                Console.WriteLine();
                Console.WriteLine("按回车键继续...");
                Console.ReadLine();
                try { Console.Clear(); } catch { }
            }
        }

        static void ShowMainMenu()
        {
            Console.WriteLine("请选择算法：");
            Console.WriteLine("  1. SM2 (非对称加密/签名)");
            Console.WriteLine("  2. SM3 (哈希算法)");
            Console.WriteLine("  3. SM4 (对称加密)");
            Console.WriteLine("  4. SM9 (标识加密)");
            Console.WriteLine("  5. ZUC (流密码)");
            Console.WriteLine("  0. 退出");
            Console.Write("选择：");
        }

        static void HandleSM2()
        {
            Console.Clear();
            Console.WriteLine("========== SM2 算法 ==========");
            Console.WriteLine();
            Console.WriteLine("请选择操作：");
            Console.WriteLine("  1. 生成密钥对");
            Console.WriteLine("  2. 公钥加密");
            Console.WriteLine("  3. 私钥解密");
            Console.WriteLine("  4. 私钥签名");
            Console.WriteLine("  5. 公钥验签");
            Console.Write("选择：");

            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    var keyPair = SM2Utils.GenerateKeyPair();
                    Console.WriteLine();
                    Console.WriteLine($"公钥：{keyPair.PublicKey}");
                    Console.WriteLine($"私钥：{keyPair.PrivateKey}");
                    break;
                case "2":
                    Console.Write("请输入明文：");
                    string plainText = Console.ReadLine();
                    Console.Write("请输入公钥：");
                    string publicKey = Console.ReadLine();
                    try
                    {
                        string encrypted = SM2Utils.Encrypt(plainText, publicKey);
                        Console.WriteLine($"加密结果：{encrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"加密失败：{ex.Message}");
                    }
                    break;
                case "3":
                    Console.Write("请输入密文：");
                    string cipherText = Console.ReadLine();
                    Console.Write("请输入私钥：");
                    string privateKey = Console.ReadLine();
                    try
                    {
                        string decrypted = SM2Utils.Decrypt(cipherText, privateKey);
                        Console.WriteLine($"解密结果：{decrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解密失败：{ex.Message}");
                    }
                    break;
                case "4":
                    Console.Write("请输入待签名数据：");
                    string signData = Console.ReadLine();
                    Console.Write("请输入私钥：");
                    string signPrivateKey = Console.ReadLine();
                    try
                    {
                        string signature = SM2Utils.Sign(signData, signPrivateKey);
                        Console.WriteLine($"签名结果：{signature}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"签名失败：{ex.Message}");
                    }
                    break;
                case "5":
                    Console.Write("请输入原始数据：");
                    string verifyData = Console.ReadLine();
                    Console.Write("请输入签名：");
                    string verifySignature = Console.ReadLine();
                    Console.Write("请输入公钥：");
                    string verifyPublicKey = Console.ReadLine();
                    try
                    {
                        bool isValid = SM2Utils.Verify(verifyData, verifySignature, verifyPublicKey);
                        Console.WriteLine($"验签结果：{(isValid ? "验证通过" : "验证失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"验签失败：{ex.Message}");
                    }
                    break;
                default:
                    Console.WriteLine("无效选择");
                    break;
            }
        }

        static void HandleSM3()
        {
            Console.Clear();
            Console.WriteLine("========== SM3 算法 ==========");
            Console.WriteLine();
            Console.WriteLine("请选择操作：");
            Console.WriteLine("  1. 计算哈希值");
            Console.WriteLine("  2. 验证哈希值");
            Console.Write("选择：");

            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    Console.Write("请输入明文：");
                    string plainText = Console.ReadLine();
                    try
                    {
                        string hash = SM3Utils.Hash(plainText);
                        Console.WriteLine($"SM3哈希值：{hash}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"计算失败：{ex.Message}");
                    }
                    break;
                case "2":
                    Console.Write("请输入明文：");
                    string verifyText = Console.ReadLine();
                    Console.Write("请输入待验证的哈希值：");
                    string expectedHash = Console.ReadLine();
                    try
                    {
                        bool isValid = SM3Utils.Verify(verifyText, expectedHash);
                        Console.WriteLine($"验证结果：{(isValid ? "验证通过" : "验证失败")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"验证失败：{ex.Message}");
                    }
                    break;
                default:
                    Console.WriteLine("无效选择");
                    break;
            }
        }

        static void HandleSM4()
        {
            Console.Clear();
            Console.WriteLine("========== SM4 算法 ==========");
            Console.WriteLine();
            Console.WriteLine("请选择操作：");
            Console.WriteLine("  1. 生成密钥");
            Console.WriteLine("  2. 生成IV");
            Console.WriteLine("  3. ECB模式加密");
            Console.WriteLine("  4. ECB模式解密");
            Console.WriteLine("  5. CBC模式加密");
            Console.WriteLine("  6. CBC模式解密");
            Console.Write("选择：");

            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    Console.WriteLine($"SM4密钥：{SM4Utils.GenerateKey()}");
                    break;
                case "2":
                    Console.WriteLine($"SM4 IV：{SM4Utils.GenerateIV()}");
                    break;
                case "3":
                    Console.Write("请输入明文：");
                    string ecbPlain = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string ecbKey = Console.ReadLine();
                    try
                    {
                        string encrypted = SM4Utils.EncryptECB(ecbPlain, ecbKey);
                        Console.WriteLine($"ECB加密结果：{encrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"加密失败：{ex.Message}");
                    }
                    break;
                case "4":
                    Console.Write("请输入密文：");
                    string ecbCipher = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string ecbDecKey = Console.ReadLine();
                    try
                    {
                        string decrypted = SM4Utils.DecryptECB(ecbCipher, ecbDecKey);
                        Console.WriteLine($"ECB解密结果：{decrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解密失败：{ex.Message}");
                    }
                    break;
                case "5":
                    Console.Write("请输入明文：");
                    string cbcPlain = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string cbcKey = Console.ReadLine();
                    Console.Write("请输入IV：");
                    string cbcIV = Console.ReadLine();
                    try
                    {
                        string encrypted = SM4Utils.EncryptCBC(cbcPlain, cbcKey, cbcIV);
                        Console.WriteLine($"CBC加密结果：{encrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"加密失败：{ex.Message}");
                    }
                    break;
                case "6":
                    Console.Write("请输入密文：");
                    string cbcCipher = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string cbcDecKey = Console.ReadLine();
                    Console.Write("请输入IV：");
                    string cbcDecIV = Console.ReadLine();
                    try
                    {
                        string decrypted = SM4Utils.DecryptCBC(cbcCipher, cbcDecKey, cbcDecIV);
                        Console.WriteLine($"CBC解密结果：{decrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解密失败：{ex.Message}");
                    }
                    break;
                default:
                    Console.WriteLine("无效选择");
                    break;
            }
        }

        static void HandleSM9()
        {
            Console.Clear();
            Console.WriteLine("========== SM9 算法 ==========");
            Console.WriteLine();
            Console.WriteLine("请选择操作：");
            Console.WriteLine("  1. 生成主密钥对");
            Console.WriteLine("  2. 派生用户公钥");
            Console.WriteLine("  3. 加密");
            Console.WriteLine("  4. 解密");
            Console.Write("选择：");

            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    var keyPair = SM9Utils.GenerateMasterKeyPair();
                    Console.WriteLine();
                    Console.WriteLine($"主公钥：{keyPair.MasterPublicKey}");
                    Console.WriteLine($"主私钥：{keyPair.MasterPrivateKey}");
                    break;
                case "2":
                    Console.Write("请输入主公钥：");
                    string masterPublicKey = Console.ReadLine();
                    Console.Write("请输入用户标识(identity)：");
                    string identity = Console.ReadLine();
                    try
                    {
                        string publicKey = SM9Utils.DerivePublicKey(masterPublicKey, identity);
                        Console.WriteLine($"派生公钥：{publicKey}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"派生失败：{ex.Message}");
                    }
                    break;
                case "3":
                    Console.Write("请输入明文：");
                    string plainText = Console.ReadLine();
                    Console.Write("请输入用户公钥：");
                    string sm9PublicKey = Console.ReadLine();
                    try
                    {
                        string encrypted = SM9Utils.Encrypt(plainText, sm9PublicKey);
                        Console.WriteLine($"加密结果：{encrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"加密失败：{ex.Message}");
                    }
                    break;
                case "4":
                    Console.Write("请输入密文：");
                    string cipherText = Console.ReadLine();
                    Console.Write("请输入主私钥：");
                    string sm9PrivateKey = Console.ReadLine();
                    Console.Write("请输入用户标识(identity)：");
                    string decryptIdentity = Console.ReadLine();
                    try
                    {
                        string decrypted = SM9Utils.Decrypt(cipherText, sm9PrivateKey, decryptIdentity);
                        Console.WriteLine($"解密结果：{decrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解密失败：{ex.Message}");
                    }
                    break;
                default:
                    Console.WriteLine("无效选择");
                    break;
            }
        }

        static void HandleZUC()
        {
            Console.Clear();
            Console.WriteLine("========== ZUC 算法 ==========");
            Console.WriteLine();
            Console.WriteLine("请选择操作：");
            Console.WriteLine("  1. 生成密钥");
            Console.WriteLine("  2. 生成IV");
            Console.WriteLine("  3. 加密");
            Console.WriteLine("  4. 解密");
            Console.Write("选择：");

            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    Console.WriteLine($"ZUC密钥：{ZUCUtils.GenerateKey()}");
                    break;
                case "2":
                    Console.WriteLine($"ZUC IV：{ZUCUtils.GenerateIV()}");
                    break;
                case "3":
                    Console.Write("请输入明文：");
                    string plainText = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string zucKey = Console.ReadLine();
                    Console.Write("请输入IV：");
                    string zucIV = Console.ReadLine();
                    try
                    {
                        string encrypted = ZUCUtils.Encrypt(plainText, zucKey, zucIV);
                        Console.WriteLine($"加密结果：{encrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"加密失败：{ex.Message}");
                    }
                    break;
                case "4":
                    Console.Write("请输入密文：");
                    string cipherText = Console.ReadLine();
                    Console.Write("请输入密钥：");
                    string zucDecKey = Console.ReadLine();
                    Console.Write("请输入IV：");
                    string zucDecIV = Console.ReadLine();
                    try
                    {
                        string decrypted = ZUCUtils.Decrypt(cipherText, zucDecKey, zucDecIV);
                        Console.WriteLine($"解密结果：{decrypted}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"解密失败：{ex.Message}");
                    }
                    break;
                default:
                    Console.WriteLine("无效选择");
                    break;
            }
        }
    }
}