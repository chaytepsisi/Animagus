using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Animagus
{
    internal class Test
    {
        static byte[] PText = new byte[] {
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

        public static void CheckCorrectness()
        {
            Console.WriteLine("Plaintext : " + CommonFunctions.ByteArrayToString(PText));
            byte[] cText = Animagus.Animagus_Encrypt(PText, Key, Tag);
            Console.WriteLine("Ciphertext: " + CommonFunctions.ByteArrayToString(cText));
            cText = Animagus.Animagus_Decrypt(cText, Key, Tag);
            Console.WriteLine("Plaintext': " + CommonFunctions.ByteArrayToString(cText));

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
    }
}
