using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Animagus
{
    internal class Constants
    {
        public static int BLOCK_BYTE_SIZE = 16;// 128/8=16
        public static int KEY_BYTE_SIZE = 16;// 128/8=16
        public static byte[] ZERO_IV = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };// CommonFunctions.GenerateZeroIV(BLOCK_BYTE_SIZE);
    }
}
