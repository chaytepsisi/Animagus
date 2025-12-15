using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Animagus
{
    internal class Animagus
    {
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
            c1 = CommonFunctions.Xor(c1, c2);

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
