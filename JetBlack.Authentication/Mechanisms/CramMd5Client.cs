using System;
using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public class CramMd5Client : CramMd5
    {
        public CramMd5Client(string userName, string password)
            : base(new FirstStep(userName, password))
        {
        }

        class FirstStep : PendingStep
        {
            private readonly string _userName;
            private readonly string _password;

            public FirstStep(string userName, string password)
            {
                if (string.IsNullOrEmpty(userName))
                    throw new ArgumentException("Value must be specified.", "userName");
                if (password == null)
                    throw new ArgumentNullException("password");

                _userName = userName;
                _password = password;

                BytesToSend = null;
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                var kMd5 = new HMACMD5(Encoding.UTF8.GetBytes(_password));
                var computedHash = kMd5.ComputeHash(bytesReceived);
                var passwordHash = BitConverter.ToString(computedHash).ToLower().Replace("-", "");
                return new SecondStep(Encoding.UTF8.GetBytes(string.Concat(_userName, ' ', passwordHash)));
            }
        }

        class SecondStep : PendingStep
        {
            public SecondStep(byte[] bytesToSend)
            {
                BytesToSend = bytesToSend;
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                return Accept;
            }
        }
    }
}
