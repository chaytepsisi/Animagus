using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Animagus
{
    internal class EncryptionManager
    {
        public AesManaged CreateAesManaged(byte[] key, byte[] iv)
        {
            return new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = iv
            };
        }
        public byte[] Encrypt(byte[] pText, byte[] key, byte[] iv)
        {
            var aesAlg = CreateAesManaged(key, iv);
            ICryptoTransform encryptor = aesAlg.CreateEncryptor();// (aesAlg.Key, aesAlg.IV);
            return encryptor.TransformFinalBlock(pText, 0, pText.Length);

        }
        public byte[] Decrypt(byte[] cText, byte[] key, byte[] iv)
        {
            var aesAlg = CreateAesManaged(key, iv);
            ICryptoTransform decryptor = aesAlg.CreateDecryptor();// (aesAlg.Key, aesAlg.IV);
            return decryptor.TransformFinalBlock(cText, 0, cText.Length);
        }

        public byte[] GenerateKeyStream(byte[] seed, byte[] key, byte[] iv, int KeyStreamLength)
        {
            var newSeed = new byte[seed.Length];
            Array.Copy(seed, newSeed, seed.Length);
            var aesAlg = CreateAesManaged(key, iv);
            ICryptoTransform encryptor = aesAlg.CreateEncryptor();//.CreateEncryptor(aesAlg.Key, aesAlg.IV);

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
