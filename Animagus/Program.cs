using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;

namespace Animagus
{
    internal class Program
    {
        static readonly byte[] PText = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
            };
        static readonly byte[] Key = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };

        static readonly byte[] Tag = new byte[] {
                0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
            };

        static void Main(string[] args)
        {
            CheckCorrectness();
            Console.WriteLine();
            //Test1();
            //Console.WriteLine();
            //Test1();
            //Console.WriteLine();
            //Test1();
            //Console.WriteLine();
            Test2();
            Console.WriteLine();
            Test2();
            Console.WriteLine();
            Test2();

        }

        static void CheckCorrectness()
        {
            Console.WriteLine("Plaintext : "+CommonFunctions.ByteArrayToString(PText));
            byte[] cText = Animagus_Encrypt(PText, Key, Tag);
            Console.WriteLine("Ciphertext: " + CommonFunctions.ByteArrayToString(cText));
            cText = Animagus_Decrypt(cText, Key, Tag);
            Console.WriteLine("Plaintext': "+CommonFunctions.ByteArrayToString(cText));

            for (int i = 0; i < cText.Length; i++)
            {
                if (cText[i] != PText[i])
                {
                    Console.WriteLine("ERROR! Wrong plaintext");
                    return;
                }
            }
            Console.WriteLine("Check successfull");
            return;
        }
        static void Test1()
        {
            Stopwatch stopwatch = new Stopwatch();
            int numberOfTrials = 100000;
            byte[] testPText = new byte[PText.Length];
            Array.Copy(PText, testPText, PText.Length); 
            stopwatch.Start();
            for (int i = 0; i < numberOfTrials; i++)
                testPText = Animagus_Encrypt(testPText, Key, Tag);

            stopwatch.Stop();

            Console.WriteLine("Total Miliseconds: " + stopwatch.ElapsedMilliseconds.ToString() + " for " + numberOfTrials + " messages of length " + testPText.Length + " bytes.");
            Console.WriteLine("Average tics/byte: " + (stopwatch.ElapsedTicks / (numberOfTrials * testPText.Length * 1.0)).ToString());
        }

        static void Test2()
        {
            Stopwatch stopwatch = new Stopwatch();
            int numberOfTrials = 100000;
            byte[] p1 = PText.Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] p2 = PText.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] pBar = PText.Skip(Constants.BLOCK_BYTE_SIZE * 2).ToArray();
            //byte[] pBar = new byte[0];// pText.Skip(Constants.BLOCK_BYTE_SIZE * 2).ToArray();

            stopwatch.Start();
            for (int i = 0; i < numberOfTrials; i++)
                Animagus_Encrypt(p1,p2,pBar, Key, Tag);

            stopwatch.Stop();

            Console.WriteLine("*Total Miliseconds: " + stopwatch.ElapsedMilliseconds.ToString() + " for " + numberOfTrials + " messages of length " + (p1.Length + p2.Length + pBar.Length)+ " bytes.");
            Console.WriteLine("*Average tics/byte: " + (stopwatch.ElapsedTicks / (numberOfTrials * (p1.Length + p2.Length + pBar.Length) * 1.0)).ToString());
        }

        public static byte[] Animagus_Encrypt(byte[] pText, byte[] key, byte[] tag)
        {
            byte[] p1 = pText.Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] p2 = pText.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] pBar = pText.Skip(Constants.BLOCK_BYTE_SIZE * 2).ToArray();

            byte[] hashResult = HashManager.ComputeStatic(pBar, tag, key);

            p2 = CommonFunctions.Xor(p2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            p1 = CommonFunctions.Xor(p1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            EncryptionManager encryptionManager = new EncryptionManager();
            p1 = encryptionManager.Encrypt(p1, key, Constants.ZERO_IV);
            p2 = encryptionManager.Encrypt(p2, key, Constants.ZERO_IV);

            p2 = CommonFunctions.Xor(p2, p1);
            var keyStream = encryptionManager.GenerateKeyStream(p2, key, Constants.ZERO_IV, pBar.Length);
            var cBar = CommonFunctions.Xor(pBar, keyStream);

            hashResult = HashManager.ComputeStatic(cBar, tag, key);
            p2 = CommonFunctions.Xor(p2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            p1 = CommonFunctions.Xor(p1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var c2 = encryptionManager.Encrypt(p2, key, Constants.ZERO_IV);
            p1 = CommonFunctions.Xor(p1, c2);
            var c1 = encryptionManager.Encrypt(p1, key, Constants.ZERO_IV);

            return c1.Concat(c2).Concat(cBar).ToArray();
        }

        public static void Animagus_Encrypt(byte[] p1, byte[] p2, byte[] pBar, byte[] key, byte[] tag)
        {
            byte[] hashResult = HashManager.ComputeStatic(pBar, tag, key);

            p2 = CommonFunctions.Xor(p2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            p1 = CommonFunctions.Xor(p1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            EncryptionManager encryptionManager = new EncryptionManager();
            p1 = encryptionManager.Encrypt(p1, key, Constants.ZERO_IV);
            p2 = encryptionManager.Encrypt(p2, key, Constants.ZERO_IV);

            p2 = CommonFunctions.Xor(p2, p1);
            var keyStream = encryptionManager.GenerateKeyStream(p2, key, Constants.ZERO_IV, pBar.Length);
            var cBar = CommonFunctions.Xor(pBar, keyStream);
            hashResult = HashManager.ComputeStatic(cBar, tag, key);
            p2 = CommonFunctions.Xor(p2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            p1 = CommonFunctions.Xor(p1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            var c2 = encryptionManager.Encrypt(p2, key, Constants.ZERO_IV);
            p1 = CommonFunctions.Xor(p1, c2);
            var c1 = encryptionManager.Encrypt(p1, key, Constants.ZERO_IV);
        }

        public static byte[] Animagus_Decrypt(byte[] cText, byte[] key, byte[] tag)
        {
            byte[] c1 = cText.Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] c2 = cText.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray();
            byte[] cBar = cText.Skip(Constants.BLOCK_BYTE_SIZE * 2).ToArray();
            
            EncryptionManager encryptionManager = new EncryptionManager();
            c1 = encryptionManager.Decrypt(c1, key, Constants.ZERO_IV);
            c1=CommonFunctions.Xor(c1, c2);

            c2 = encryptionManager.Decrypt(c2, key, Constants.ZERO_IV);

            var hashManager = new HashManager(cBar, tag, key);
            byte[] hashResult = hashManager.Compute();
            c2 = CommonFunctions.Xor(c2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            c1 = CommonFunctions.Xor(c1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());
           
            var keyStream = encryptionManager.GenerateKeyStream(c2, key, Constants.ZERO_IV, cBar.Length);
            var pBar = CommonFunctions.Xor(cBar, keyStream);

            c2 = CommonFunctions.Xor(c2, c1);
            c1 = encryptionManager.Decrypt(c1, key, Constants.ZERO_IV);
            c2 = encryptionManager.Decrypt(c2, key, Constants.ZERO_IV);
           
            hashManager = new HashManager(pBar, tag, key);
            hashResult = hashManager.Compute();

            var p2 = CommonFunctions.Xor(c2, hashResult.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            var p1 = CommonFunctions.Xor(c1, hashResult.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            return p1.Concat(p2).Concat(pBar).ToArray();
        }
    }
}
