using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Animagus
{
    internal class HashManager
    {
        public byte[] Input { get; set; }
        public byte[] Tag { get; set; }
        public byte[] Key { get; set; }

        public HashManager(byte[] pBar, byte[] tag, byte[] key)
        {
            Input = pBar;
            Tag = tag;
            Key = key;
        }

        public byte[] Compute()
        {
            using (var hmacSha256 = new HMACSHA256(Key))
            {
                return hmacSha256.ComputeHash(Input.Concat(new byte[] { 0x1 }).Concat(Tag).ToArray());
            }
            //using ( var hmacSha512=new HMACSHA512(Key))
            //{
            //    return hmacSha512.ComputeHash(Input.Concat(new byte[] { 0x1 }).Concat(Tag).ToArray());
            //}
        }

        public static byte[] ComputeStatic(byte[] pBar, byte[] tag, byte[] key)
        {
            using (var hmacSha256 = new HMACSHA256(key))
            {
                return hmacSha256.ComputeHash(pBar.Concat(new byte[] { 0x1 }).Concat(tag).ToArray());
            }
        }
    }
}
