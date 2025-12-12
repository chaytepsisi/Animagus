using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Animagus
{
    internal class EncryptionManager_Slow
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }

        readonly AesManaged aesManaged;
        readonly ICryptoTransform encryptor;
        ICryptoTransform decryptor;
        public EncryptionManager_Slow(byte[] key, byte[] iv = null)
        {
            Key = key;
            if (iv == null)
                iv = CommonFunctions.GenerateZeroIV(Constants.BLOCK_BYTE_SIZE);
            aesManaged = new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = iv
            };
            encryptor = aesManaged.CreateEncryptor(Key, IV);
            decryptor = aesManaged.CreateDecryptor(Key, IV);
        }

        public byte[] Encrypt(byte[] pText)
        {
            return encryptor.TransformFinalBlock(pText, 0, pText.Length);
        }
        public byte[] Decrypt(byte[] cText, byte[] Key, byte[] IV = null)
        {
            return decryptor.TransformFinalBlock(cText, 0, cText.Length);
        }

        public byte[] GenerateKeyStream(byte[] seed, int KeyStreamLength)
        {
            byte[] newSeed = new byte[seed.Length];
            Array.Copy(seed, newSeed, seed.Length);

            int limit = (int)Math.Ceiling(KeyStreamLength * 1.0 / Constants.BLOCK_BYTE_SIZE);

            List<byte> output = new List<byte>();
            for (int i = 0; i < limit; i++)
            {
                output.AddRange(encryptor.TransformFinalBlock(newSeed, 0, newSeed.Length));
                newSeed = CommonFunctions.IncrementArray(newSeed);
            }
            if (output.Count > KeyStreamLength)
                return output.Take(KeyStreamLength).ToArray();
            return output.ToArray();
        }
    }
}
