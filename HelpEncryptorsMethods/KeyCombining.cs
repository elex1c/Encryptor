namespace Encryptor.HelpEncryptorsMethods
{
    public static class KeyCombining
    {
        public class Keys
        {
            public string Key { get; set; }
            public string IV { get; set; }
        }

        public static string CombineKeys(string Key, string IV)
        {
            string combined = IV.Length.ToString() + "?";
            for (int i = 0; i < Key.Length; i++)
            {
                if (i < IV.Length)
                {
                    combined += Key[i];
                    combined += IV[i];
                }
                else
                {
                    combined += Key[i];
                }
            }
            return combined;
        }

        public static Keys UnCombineKeys(string key)
        {
            string ivLenght = key.Split('?')[0];
            if (int.TryParse(ivLenght, null, out int ivLenghtInt))
            {
                string Key = "", IV = "";
                int symbolCounter = 1;
                for (int i = ivLenght.Length + 1; i < ivLenghtInt * 2 + ivLenght.Length + 1; i++)
                {
                    try
                    {
                        if (symbolCounter % 2 == 1)
                            Key += key[i];
                        else
                            IV += key[i];
                    }
                    catch (Exception)
                    {
                        throw new ArgumentException("You've sent invalide key");
                    }

                    symbolCounter++;
                }
                Key += key.Substring(ivLenght.Length + 1 + ivLenghtInt * 2);

                return new Keys { Key = Key, IV = IV };
            }
            else
                throw new FormatException("The key you sent is invalid!");
        }
    }
}
