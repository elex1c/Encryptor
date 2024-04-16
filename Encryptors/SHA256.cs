namespace Encryptor.Encryptors
{
    public static class SHA256
    {
        public static byte[] Encrypt(byte[] byteToEncrypt)
        {
            var sha = System.Security.Cryptography.SHA256.Create();

            return sha.ComputeHash(byteToEncrypt);
        }
    }
}
