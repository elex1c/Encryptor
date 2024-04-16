using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Encryptor.HelpEncryptorsMethods;

namespace Encryptor.Encryptors
{
    public static class AES
    {
        public static EncryptionData Encrypt(byte[] encryptData)
        {
            using Aes aes = Aes.Create();

            byte[] encryptedBytes = EncryptBytes(encryptData, aes.Key, aes.IV);
            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedBytes),
                Base64Key = KeyCombining.CombineKeys(Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV))
            };
        }

        public static EncryptionData Encrypt(byte[] encryptData, int keySize)
        {
            using Aes aes = Aes.Create();
            aes.KeySize = keySize;
            aes.GenerateKey();

            byte[] encryptedBytes = EncryptBytes(encryptData, aes.Key, aes.IV);
            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedBytes),
                Base64Key = KeyCombining.CombineKeys(Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV))
            };
        }

        public static EncryptionData Encrypt(byte[] encryptData, string key)
        {
            using Aes aes = Aes.Create();

            var keys = KeyCombining.UnCombineKeys(key);
            try
            {
                aes.Key = Convert.FromBase64String(keys.Key);
                aes.IV = Convert.FromBase64String(keys.IV);
            }
            catch (Exception)
            {
                throw new ArgumentException("You've sent invalide key");
            }

            byte[] encryptedBytes = EncryptBytes(encryptData, aes.Key, aes.IV);
            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedBytes),
                Base64Key = KeyCombining.CombineKeys(Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV))
            };
        }

        public static byte[] Decrypt(EncryptionData encryptionData)
        {
            if (encryptionData == null)
                throw new ArgumentNullException("Encryption data can't equal null!");
            if (string.IsNullOrEmpty(encryptionData.Base64EncryptedData))
                throw new ArgumentNullException("Encrypted data stirng can't equal null or be empty!");
            if (string.IsNullOrEmpty(encryptionData.Base64Key))
                throw new ArgumentNullException("Key stirng can't equal null or be empty!");

            var keyData = KeyCombining.UnCombineKeys(encryptionData.Base64Key);

            return DecryptBytes(Convert.FromBase64String(encryptionData.Base64EncryptedData),
                    Convert.FromBase64String(keyData.Key),
                    Convert.FromBase64String(keyData.IV));
        }

        static byte[] EncryptBytes(byte[] encryptData, byte[] Key, byte[] IV)
        {
            if (encryptData.Length < 0)
                throw new ArgumentNullException("Data can't be empty");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

                encrypted = aes.EncryptCbc(encryptData, IV);
            }

            return encrypted;
        }

        static byte[] DecryptBytes(byte[] encryptedBytes, byte[] Key, byte[] IV)
        {
            if (encryptedBytes == null || encryptedBytes.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] decrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

                decrypted = aes.DecryptCbc(encryptedBytes, IV);
            }

            return decrypted;
        }
    }
}
