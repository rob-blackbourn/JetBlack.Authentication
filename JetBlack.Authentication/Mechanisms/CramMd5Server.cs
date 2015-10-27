using System;
using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public interface ICramMd5User
    {
        string UserName { get; }
        string Password { get; }
        bool IsImpersonateable(string authenticationId);
    }

    public class CramMd5Server : CramMd5
    {
        public CramMd5Server(Func<string,ICramMd5User> fetchUser, string hostName)
            : base(new FirstStep(hostName, fetchUser))
        {
        }

        class FirstStep : PendingStep
        {
            private readonly Func<string, ICramMd5User> _fetchUser;
            private readonly string _key;

            public FirstStep(string hostName, Func<string, ICramMd5User> fetchUser)
            {
                if (fetchUser == null)
                    throw new ArgumentNullException("fetchUser");

                _fetchUser = fetchUser;
                _key = string.Concat('<', Guid.NewGuid(), '@', hostName, '>');
                BytesToSend = Encoding.UTF8.GetBytes(_key); 
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                // Parse client response. response = userName SP hash.
                var parts = Encoding.UTF8.GetString(bytesReceived).Split(' ');
                if (parts.Length != 2 || string.IsNullOrEmpty(parts[0]))
                    return Reject;

                var userName = parts[0];
                var user = _fetchUser(userName);
                if (user == null)
                    return Reject;

                var computedHash = HmacMd5(_key, user.Password);
                var hash = BitConverter.ToString(computedHash).ToLower().Replace("-", "");
                if (hash != parts[1])
                    return Reject;
                
                return Accept;
            }

            private static byte[] HmacMd5(string hashKey, string text)
            {
                var kMd5 = new HMACMD5(Encoding.Default.GetBytes(text));
                return kMd5.ComputeHash(Encoding.ASCII.GetBytes(hashKey));
            }
        }
    }
}
