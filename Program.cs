using System;
using System.IO; // Dodane, aby użyć MemoryStream, CryptoStream, StreamReader, StreamWriter
using System.Security.Cryptography; // Dodane, aby użyć SymmetricAlgorithm, AesManaged
using System.Text; // Dodane, aby użyć StringBuilder
using LiveCharts; // Dodane, aby użyć LiveCharts


namespace CipherApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Witaj w aplikacji szyfrującej!");

            // Wybór algorytmu szyfrowania (AES w przykładzie)
            using (Aes algorithm = Aes.Create())
            {
                // Generowanie kluczy i IV
                algorithm.GenerateKey();
                algorithm.GenerateIV();

                // Przykładowa wiadomość do szyfrowania
                string originalMessage = "Hello, world!";

                // Szyfrowanie
                byte[] encrypted = EncryptStringToBytes_Aes(originalMessage, algorithm.Key, algorithm.IV);

                // Deszyfrowanie
                string decrypted = DecryptStringFromBytes_Aes(encrypted, algorithm.Key, algorithm.IV);

                // Wyświetlanie wyników
                Console.WriteLine($"Oryginalna wiadomość: {originalMessage}");
                Console.WriteLine($"Zaszyfrowana wiadomość (HEX): {ByteArrayToHexString(encrypted)}");
                Console.WriteLine($"Odszyfrowana wiadomość: {decrypted}");
                Console.WriteLine($"Klucz (HEX): {ByteArrayToHexString(algorithm.Key)}");
                Console.WriteLine($"IV (HEX): {ByteArrayToHexString(algorithm.IV)}");
            }

            Console.ReadLine();
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Utworzenie szyfratora, który jest używany do wykonywania operacji szyfrowania
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Strumienie do szyfrowania tekstu
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Zapisz wszystkie dane do strumienia
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Utworzenie deszyfratora, który jest używany do wykonywania operacji deszyfrowania
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Strumienie do deszyfrowania tekstu
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Odczytaj wszystkie dane z deszyfrowanego strumienia
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static string ByteArrayToHexString(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
