namespace Encryptor.Encryptors
{
    public static class SHA512
    {
        public static byte[] Encrypt(byte[] byteToEncrypt)
        {
            var sha = System.Security.Cryptography.SHA512.Create();

            return sha.ComputeHash(byteToEncrypt);
        }
    }
}
