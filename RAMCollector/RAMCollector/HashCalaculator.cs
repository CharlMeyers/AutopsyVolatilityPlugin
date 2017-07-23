using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RAMCollector
{
    class HashCalaculator
    {
        public static void CalculateHash(string fileName)
        {
            byte[] hash;
            try
            {
                Console.WriteLine("Computing file hash...");
                if (fileName != null && fileName != "")
                {
                    using (var md5 = new MD5CryptoServiceProvider())
                    {
                        using (var stream = File.OpenRead(fileName))
                        {
                            hash = md5.ComputeHash(stream);
                        }
                    }

                    var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant().Trim();

                    using (var stream = new StreamWriter(File.OpenWrite(fileName.Replace("raw", "Hash.txt")), Encoding.UTF8))
                    {
                        stream.Write(hashString);
                    }

                    Console.WriteLine(fileName);

                    Console.WriteLine("The computed hash for the dump is:");
                    Console.WriteLine(BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant().Trim());
                    Console.WriteLine("This has been saved in a file along with the RAM dump");                    
                }
                else
                {
                    Console.WriteLine("No memory dump file found to calculate hash on.");                    
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Error at hash calculator:");
                Console.WriteLine("Cannot find the file to calculate hash on");

                throw;
            }            
        }
    }
}
