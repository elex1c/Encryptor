using System.Security.Cryptography;

namespace Encryptor.Encryptors
{
    public class DES
    {
        public static EncryptionData Encrypt(byte[] dataToEncrypt)
        {
            byte[] key;
            byte[] IV;

            using (TripleDES des = TripleDES.Create())
            {
                key = des.Key;
                IV = des.IV;
            }

            byte[] encryptedBytes = Encrypt_TripleDES(dataToEncrypt, key, IV);

            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedBytes),
                Base64Key = HelpEncryptorsMethods.KeyCombining
                    .CombineKeys(Convert.ToBase64String(key), Convert.ToBase64String(IV))
            };
        }

        public static EncryptionData Encrypt(byte[] dataToEncrypt, string twoKeys)
        {
            byte[] key;
            byte[] IV;

            var keys = HelpEncryptorsMethods.KeyCombining.UnCombineKeys(twoKeys);

            try
            {
                key = Convert.FromBase64String(keys.Key);
                IV = Convert.FromBase64String(keys.IV);
            }
            catch (Exception)
            {
                throw new ArgumentException("You've sent invalide key");
            }

            using (TripleDES des = TripleDES.Create())
            {
                des.Key = key;
                des.IV = IV;
            }

            byte[] encryptedBytes = Encrypt_TripleDES(dataToEncrypt, key, IV);

            return new EncryptionData
            {
                Base64EncryptedData = Convert.ToBase64String(encryptedBytes),
                Base64Key = HelpEncryptorsMethods.KeyCombining
                    .CombineKeys(Convert.ToBase64String(key), Convert.ToBase64String(IV))
            };
        }

        public static byte[] Decrypt(EncryptionData encryptionData)
        {
            if (string.IsNullOrEmpty(encryptionData.Base64EncryptedData))
                throw new ArgumentNullException("You've sent empty encrypted data.");
            if (string.IsNullOrEmpty(encryptionData.Base64Key))
                throw new ArgumentNullException("You've sent empty encryption key.");

            var keys = HelpEncryptorsMethods.KeyCombining
                .UnCombineKeys(encryptionData.Base64Key);

            return Decrypt_TripleDES(Convert.FromBase64String(encryptionData.Base64EncryptedData),
                Convert.FromBase64String(keys.Key),
                Convert.FromBase64String(keys.IV));
        }

        private static byte[] Encrypt_TripleDES(byte[] dataToEncrypt, byte[] key, byte[] IV)
        {
            if (dataToEncrypt.Length < 0)
                throw new ArgumentNullException("You've sent empty data to encrypt.");

            byte[] encrypted;

            using (var des = TripleDES.Create())
            {
                des.Key = key;
                des.IV = IV;
                des.Mode = CipherMode.CBC;

                encrypted = des.EncryptCbc(dataToEncrypt, IV, paddingMode: PaddingMode.PKCS7);
            }

            return encrypted;
        }

        private static byte[] Decrypt_TripleDES(byte[] encrypted, byte[] key, byte[] IV)
        {
            byte[] decrypted;

            using (var des = TripleDES.Create())
            {
                des.Key = key;
                des.IV = IV;
                des.Mode = CipherMode.CBC;

                decrypted = des.DecryptCbc(encrypted, IV, paddingMode: PaddingMode.PKCS7);
            }

            return decrypted;
        }
    }
}
