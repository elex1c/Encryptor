using System.Security.Cryptography;

namespace Encryptor.Encryptors
{
    public static class RSA
    {
        public static EncryptionData Encrypt(byte[] dataToEncrypt)
        {
            byte[] encryptedData;
            byte[] key;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                encryptedData = RSAEncrypt(dataToEncrypt, rsa.ExportParameters(true), false);
                key = rsa.ExportPkcs8PrivateKey();
            }

            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedData),
                Base64Key = Convert.ToBase64String(key)
            };
        }

        public static EncryptionData Encrypt(byte[] dataToEncrypt, int keySize)
        {
            byte[] encryptedData;
            byte[] key;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
            {
                try
                {
                    encryptedData = RSAEncrypt(dataToEncrypt, rsa.ExportParameters(true), false);
                }
                catch (Exception)
                {
                    throw new Exception("Invalide key size!");
                }
                key = rsa.ExportPkcs8PrivateKey();
            }

            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedData),
                Base64Key = Convert.ToBase64String(key)
            };
        }

        public static EncryptionData Encrypt(byte[] dataToEncrypt, string base64key)
        {
            byte[] key;
            byte[] encryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    key = Convert.FromBase64String(base64key);

                    rsa.ImportPkcs8PrivateKey(key, out int read);
                    encryptedData = RSAEncrypt(dataToEncrypt, rsa.ExportParameters(true), false);
                }
                catch (Exception)
                {
                    throw new ArgumentException("You've sent invalide key");
                }
            }

            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedData),
                Base64Key = Convert.ToBase64String(key)
            };
        }

        public static byte[] Decrypt(EncryptionData encryptionData)
		{
			byte[] encryptedData = Convert.FromBase64String(encryptionData.Base64EncryptedData);
			byte[] key = Convert.FromBase64String(encryptionData.Base64Key);

            return RSADecrypt(encryptedData, key, false);
        }

		private static byte[] RSAEncrypt(byte[] data, RSAParameters rsaKeyInfo, bool doOAEPadding)
		{
            if (data.Length < 0)
                throw new ArgumentNullException("You've sent empty data to encrypt.");

            byte[] encryptedData;

            using (RSACryptoServiceProvider encrypter = new RSACryptoServiceProvider())
            {
                encrypter.ImportParameters(rsaKeyInfo);

                encryptedData = encrypter.Encrypt(data, doOAEPadding);
            }

            return encryptedData;
        }

		private static byte[] RSADecrypt(byte[] data, byte[] key, bool doOAEPadding)
		{
            byte[] decryptedBytes;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportPkcs8PrivateKey(key, out int readBytes);

                decryptedBytes = rsa.Decrypt(data, doOAEPadding);
            }

            return decryptedBytes;
        }
    }
}
