using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public abstract class ScramSha1 : ISaslMechanism
    {
        protected ScramSha1(ISaslStep initialStep)
        {
            InitialStep = initialStep;
        }

        public string Name
        {
            get { return "SCRAM-SHA-1"; }
        }

        public ISaslStep InitialStep { get; private set; }

        public static string PrepUsername(string username)
        {
            return username.Replace("=", "=3D").Replace(",", "=2C");
        }

        protected static byte[] XOR(byte[] a, byte[] b)
        {
            var result = new byte[a.Length];
            for (var i = 0; i < a.Length; ++i)
                result[i] = (byte)(a[i] ^ b[i]);

            return result;
        }

        protected static byte[] H(byte[] data)
        {
            using (var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        protected static byte[] Hi(string password, byte[] salt, int iterations)
        {
            return new Rfc2898DeriveBytes(password, salt, iterations).GetBytes(20); // this is length of output of a sha-1 hmac
        }

        protected static byte[] HMAC(byte[] data, string key)
        {
            using (var hmac = new HMACSHA1(data, true))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }
    }
}
