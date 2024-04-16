namespace Encryptor.HelpEncryptorsMethods
{
    public static class ImageConvertor
    {
        public static byte[] GetBytes(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("File was not found");

            return File.ReadAllBytes(path);
        }

        public static void GetImage(string destPath, byte[] imageBytes)
        {
            using (FileStream fs = File.Create(destPath)) { }

            File.WriteAllBytes(destPath, imageBytes);
        }
    }
}
