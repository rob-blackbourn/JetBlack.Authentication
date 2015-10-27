using System;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public interface IScramSha1User
    {
        string UserName { get; }
        string SaltedPassword { get; }
        string Salt { get; }
        int Iterations { get; }
    }

    public class ScramSha1Server : ScramSha1
    {
        public ScramSha1Server(Func<string, IScramSha1User> fetchUser, Func<string> nonceGenerator)
            : base(new FirstStep(fetchUser, nonceGenerator))
        {
        }

        class FirstStep : PendingStep
        {
            private readonly Func<string, IScramSha1User> _fetchUser;
            private readonly Func<string> _nonceGenerator;

            public FirstStep(Func<string, IScramSha1User> fetchUser, Func<string> nonceGenerator)
            {
                _fetchUser = fetchUser;
                _nonceGenerator = nonceGenerator;
                BytesToSend = null;
            }

            /*
             * Parse client-first-message of the forms:
             * n,a=authzid,n=encoded-username,r=client-nonce
             * n,,n=encoded-username,r=client-nonce
             *
             * Generate server-first-message on the form:
             * r=client-nonce|server-nonce,s=user-salt,i=iteration-count
             *
             * NOTE: we are ignoring the authorization ID part of the message
             */
            public override ISaslStep Next(byte[] bytesReceived)
            {
                var stringReceived = Encoding.UTF8.GetString(bytesReceived);

                if (string.IsNullOrWhiteSpace(stringReceived))
                    return Reject;

                var parts = stringReceived.Split(',');

                if (parts.Length != 4)
                    return Reject;

                if (parts[0] != "n")
                    return Reject; // incorrect message prefix.

                string authzId;
                if (parts[1] == "a=" && parts[1].Length > 3)
                    authzId = DecodeUsername(parts[1].Substring(2));
                else if (parts[1].Length == 0)
                    authzId = string.Empty;
                else
                    return Reject; // incorrect authzid.

                if (!parts[2].StartsWith("n=") || parts[2].Length < 3)
                    return Reject; // incorrect username
                var userName = DecodeUsername(parts[2].Substring(2));

                if (!parts[3].StartsWith("r=") || parts[3].Length < 6)
                    return Reject; // invalid nonce.
                var clientNonce = parts[3].Substring(2);

                var user = _fetchUser(userName);
                if (user == null)
                    return Reject;

                var clientFirstMessageBare = parts[2] + "," + parts[3];

                return new SecondStep(clientFirstMessageBare, user.SaltedPassword, user.Salt, user.Iterations, clientNonce, _nonceGenerator);
            }

            private static string DecodeUsername(string username)
            {
                return username.Replace("=3D", "=").Replace("=2C", ",");
            }
        }

        class SecondStep : PendingStep
        {
            private readonly string _clientFirstMessageBare;
            private readonly string _clientNonce;
            private readonly byte[] _saltedPassword;
            private readonly string _serverNonce;

            public SecondStep(string clientFirstMessageBare, string saltedPassword, string salt, int iterations, string clientNonce, Func<string> nonceGenerator)
            {
                _clientFirstMessageBare = clientFirstMessageBare;
                _clientNonce = clientNonce;
                _saltedPassword = Convert.FromBase64String(saltedPassword);
                _serverNonce = nonceGenerator();
                var serverFirstMessage = "r=" + clientNonce + _serverNonce + ",s=" + salt + ",i=" + iterations;
                BytesToSend = Encoding.UTF8.GetBytes(serverFirstMessage);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                var clientFinalMessage = Encoding.UTF8.GetString(bytesReceived);

                var parts = clientFinalMessage.Split(',');

                if (parts.Length != 3)
                    return Reject;

                if (!(parts[0].StartsWith("c=") && parts[0].Length > 3))
                    return Reject;

                if (parts[1] != "r=" + _clientNonce + _serverNonce)
                    return Reject;

                if (!(parts[2].StartsWith("p=") && parts[2].Length > 3))
                    return Reject;
                var clientProof = parts[2].Substring(2);
                var clientFinalMessageWithoutProof = parts[0] + "," + parts[1];

                var clientKey = HMAC(_saltedPassword, "Client Key");
                var storedKey = H(clientKey);
                var authMessage = _clientFirstMessageBare + "," + Encoding.UTF8.GetString(BytesToSend) + "," + clientFinalMessageWithoutProof;
                var clientSignature = HMAC(storedKey, authMessage);
                var calculatedClientProof = Convert.ToBase64String(XOR(clientKey, clientSignature));

                if (clientProof != calculatedClientProof)
                    return Reject;

                return new ThirdStep(_saltedPassword, authMessage);
            }
        }

        class ThirdStep : PendingStep
        {
            public ThirdStep(byte[] saltedPassword, string authMessage)
            {
                var serverKey = HMAC(saltedPassword, "Server Key");
                var serverSignature = Convert.ToBase64String(HMAC(serverKey, authMessage));
                BytesToSend = Encoding.UTF8.GetBytes("v=" + serverSignature);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                return Accept;
            }
        }
    }
}
