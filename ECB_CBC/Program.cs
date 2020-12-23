using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ECS_CBC
{
    class Program
    {
        static void Main(string[] args)
        {
            var key = "0000000000000000000000000000000000000000000000000000000000000000";
            var keyByte = StringToByte(key);
            var iv = "0000000000000000000000000000000000000000000000000000000000000000";
            var ivByte = StringToByte(iv);
            var desEBC = new SimpleDES(keyByte, ivByte, CipherMode.ECB);
            var desCBC = new SimpleDES(keyByte, ivByte, CipherMode.CBC);


            var txt1 = "0000000000000000000000000000000000000000000000000000000000000000";
            var txt2 = "1111111111111111111111111111111111111111111111111111111111111111";
            var txt3 = "0000000000000000000000000000000000000000000000000000000000000000";
            var txt = txt1 + txt2 + txt3;

            var txtByte = StringToByte(txt);



            Console.WriteLine("Text: ");
            PrintEncoded(DataArray(txt));
            Console.WriteLine();
            Console.WriteLine("Key: " + key);
            Console.WriteLine("IV: " + iv);
            Console.WriteLine();

            var encodedEBC = desEBC.Encrypt(txtByte);
            var encodedCBC = desCBC.Encrypt(txtByte);

            var encodedStringsEBC = encodedEBC.Select(x => Convert.ToString(x, 2).PadLeft(8, '0')).ToArray();
            var encodedStringsCBC = encodedCBC.Select(x => Convert.ToString(x, 2).PadLeft(8, '0')).ToArray();


            Console.WriteLine("-----Encoded-----");
            var encodedBinaryEBC = "";
            var encodedBinaryCBC = "";

            foreach (var item in encodedStringsEBC)
                encodedBinaryEBC += item;

            foreach (var item in encodedStringsCBC)
                encodedBinaryCBC += item;

            var formtedEBC = DataArray(encodedBinaryEBC);
            var formtedCBC = DataArray(encodedBinaryCBC);

            Console.WriteLine("CBC:");
            PrintEncoded(formtedCBC);
            Console.WriteLine();
            Console.WriteLine("EBC:");
            PrintEncoded(formtedEBC);



            var decodedEBC = desEBC.Decrypt(encodedEBC);
            var decodedCBC = desCBC.Decrypt(encodedCBC);

            var dstringEBC = decodedEBC.Select(x => Convert.ToString(x, 2).PadLeft(8, '0')).ToArray();
            string dArrayEBC = "";
            foreach (var item in dstringEBC)
                dArrayEBC += item;

            var dstringCBC = decodedCBC.Select(x => Convert.ToString(x, 2).PadLeft(8, '0')).ToArray();
            string dArrayCBC = "";
            foreach (var item in dstringCBC)
                dArrayCBC += item;

            var formatedDecEBC = DataArray(dArrayEBC);
            var formatedDecCBC = DataArray(dArrayCBC);

            Console.WriteLine();
            Console.WriteLine("-----Decoded-----");
            Console.WriteLine("EBC");
            PrintEncoded(formatedDecEBC);
            Console.WriteLine();
            Console.WriteLine("CBC");
            PrintEncoded(formatedDecEBC);

            Console.ReadKey();
        }

        static void PrintEncoded(string[] encoded)
        {
            foreach (var item in encoded)
            {
                Console.WriteLine(item);
            }
        }

        static string[] DataArray(string s)
        {
            var formated = new string[s.Length / 64];
            for (int i = 0; i < s.Length / 64; i++)
            {
                formated[(s.Length / 64) - ((s.Length / 64) - i)] = s.Substring(64 * i, 64);
            }
            return formated;
        }

        static byte[] StringToByte(string s)
        {
            string input = s;
            int numOfBytes = input.Length / 8;
            byte[] bytes = new byte[numOfBytes];
            for (int i = 0; i < numOfBytes; ++i)
            {
                bytes[i] = Convert.ToByte(input.Substring(8 * i, 8), 2);
            }
            return bytes;
        }
    }

    public class SimpleDES
    {
        private byte[] IV;
        private byte[] mKey;
        private DESCryptoServiceProvider des;

        public SimpleDES(byte[] aKey, byte[] iv, CipherMode mode)
        {
            if (aKey.Length != 8)
                throw new Exception("Key size must be 8 bytes");
            mKey = aKey;
            des = new DESCryptoServiceProvider();
            des.BlockSize = 64;
            des.KeySize = 64;
            des.Padding = PaddingMode.None;
            des.Mode = mode;
            IV = iv;
        }

        public SimpleDES(byte[] aKey, byte[] iv)
        {
            if (aKey.Length != 8)
                throw new Exception("Key size must be 8 bytes");
            mKey = aKey;
            des = new DESCryptoServiceProvider();
            des.BlockSize = 64;
            des.KeySize = 64;
            des.Padding = PaddingMode.None;
            des.Mode = CipherMode.CBC;
            IV = iv;
        }

        public byte[] Encrypt(byte[] data)
        {

            ICryptoTransform encryptor = des.CreateWeakEncryptor(mKey, IV, 0);
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        public byte[] Decrypt(byte[] data)
        {
            ICryptoTransform decryptor = des.CreateWeakDecryptor(mKey, IV);
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }

    public static class DESCryptoExtensions
    {
        public static ICryptoTransform CreateWeakEncryptor(this DESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv, int mode)
        {
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, mode };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakEncryptor(this DESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakEncryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV, 0);
        }

        public static ICryptoTransform CreateWeakDecryptor(this DESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv)
        {
            return CreateWeakEncryptor(cryptoProvider, key, iv, 1);
        }

        public static ICryptoTransform CreateWeakDecryptor(this DESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakDecryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }
    }
}
