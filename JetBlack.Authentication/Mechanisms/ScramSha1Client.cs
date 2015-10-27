using System;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public class ScramSha1Client : ScramSha1
    {
        public ScramSha1Client(string userName, string password, Func<string> nonceGenerator)
            : base(new FirstStep(userName, password, nonceGenerator))
        {
        }

        class FirstStep : PendingStep
        {
            private readonly string _password;
            private readonly string _clientNonce;
            private readonly string _clientFirstMessageBare;

            public FirstStep(string userName, string password, Func<string> nonceGenerator)
            {
                if (string.IsNullOrWhiteSpace(userName))
                    throw new ArgumentException("Must specify", "userName");

                _password = password;
                const string gs2Header = "n,,";
                _clientNonce = nonceGenerator();

                _clientFirstMessageBare = "n=" + PrepUsername(userName) + "," + "r=" + _clientNonce;
                var clientFirstMessage = gs2Header + _clientFirstMessageBare;

                BytesToSend = Encoding.UTF8.GetBytes(clientFirstMessage);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                // r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
                var serverFirstMessage = Encoding.UTF8.GetString(bytesReceived);

                var parts = serverFirstMessage.Split(',');
                if (parts.Length != 3)
                    return Reject;

                if (!(parts[0].StartsWith("r=" + _clientNonce) && parts[0].Length > 3 + _clientNonce.Length))
                    return Reject;

                if (!(parts[1].StartsWith("s=") && parts[1].Length > 3))
                    return Reject;
                var salt = parts[1].Substring(2);

                int iterations;
                if (!(parts[2].StartsWith("i=") && parts[2].Length > 3 && int.TryParse(parts[2].Substring(2), out iterations)))
                    return Reject;

                const string gs2Header = "n,,";
                var channelBinding = "c=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(gs2Header));
                var clientFinalMessageWithoutProof = channelBinding + "," + parts[0];

                var saltedPassword = Hi(_password, Convert.FromBase64String(salt), iterations);

                var clientKey = HMAC(saltedPassword, "Client Key");
                var storedKey = H(clientKey);
                var authMessage = _clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof;
                var clientSignature = HMAC(storedKey, authMessage);
                var clientProof = XOR(clientKey, clientSignature);
                var serverKey = HMAC(saltedPassword, "Server Key");
                var serverSignature = HMAC(serverKey, authMessage);

                var proof = "p=" + Convert.ToBase64String(clientProof);
                var clientFinalMessage = clientFinalMessageWithoutProof + "," + proof;

                return new ClientLast(clientFinalMessage, serverSignature);
            }
        }

        class ClientLast : PendingStep
        {
            private readonly byte[] _serverSignature;

            public ClientLast(string clientFinalMessage, byte[] serverSignature)
            {
                _serverSignature = serverSignature;
                BytesToSend = Encoding.UTF8.GetBytes(clientFinalMessage);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                var serverFinalMessage = Encoding.UTF8.GetString(bytesReceived);

                if (!(serverFinalMessage.StartsWith("v=") && serverFinalMessage.Length > 3))
                    return Reject;

                var serverSignature = serverFinalMessage.Substring(2);

                if (!ConstantTimeEquals(_serverSignature, Convert.FromBase64String(serverSignature)))
                    return Reject;

                return Accept;
            }

            private static bool ConstantTimeEquals(byte[] a, byte[] b)
            {
                var diff = a.Length ^ b.Length;
                for (var i = 0; i < a.Length && i < b.Length; ++i)
                    diff |= a[i] ^ b[i];

                return diff == 0;
            }
        }
    }
}
