using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    class Program
    {
  
        public static void Main()
        {
            Stopwatch stop = new Stopwatch();
            Program pg = new Program();
            Console.WriteLine("Enter text that needs to be encrypted..");
            string data = Console.ReadLine();
            pg.EncryptAesManaged(data);
            Console.ReadLine();
        }
        public  void EncryptAesManaged(string raw)
        {
            try
            {
                //Yeni bir anahtar ve başlatma vektörü (IV) oluşturan Aes oluşturma
                //Şifreleme ve şifre çözmede aynı anahtar kullanılmalıdır
                using (AesManaged aes = new AesManaged())
                {
                    // Encrypt string    
                    byte[] encrypted = Encrypt(raw, aes.Key, aes.IV);
                    // Şifreli Metin Yazdırma
                    Console.WriteLine("Encrypted data"+(System.Text.Encoding.UTF8.GetString(encrypted)));
                    // Şifresi Çözülmüş metin.    
                    string decrypted = Decrypt(encrypted, aes.Key, aes.IV);
                    // Print decrypted string. It should be same as raw data    
                    Console.WriteLine( "Decrypted data"+ decrypted);
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            Console.ReadKey();
        }
        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            //  AesManaged yazma.    
            using (AesManaged aes = new AesManaged())
            {
                //Şifreleyici oluşturma 
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                // MemoryStream  oluşturma(Kısa bir süre için bellekte tutulacak akım (stream) oluşturur.)
                using (MemoryStream ms = new MemoryStream())
                {
                    //CryptoStream sınıfını kullanarak kripto akışı oluşturun. Bu sınıf şifrelemenin anahtarıdır
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // StreamWriter oluşturun ve bir akışa veri yazın    
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data    
            return encrypted;
        }
        static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create AesManaged    
            using (AesManaged aes = new AesManaged())
            {
                // Create a decryptor    
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }
    }
}

