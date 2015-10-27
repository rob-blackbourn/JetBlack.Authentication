using System;
using System.Collections.Generic;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public interface IPlainUser
    {
        string UserName { get; }
        string Password { get; }
        bool IsImpersonateable(string authenticationId);
    }

    public delegate bool PlainAuthenticator(string authorizationId, string username, string password);

    public class PlainServer : Plain
    {
        public PlainServer(Func<string,IPlainUser> fetchUser)
            : base(new FirstStep(fetchUser))
        {
        }

        public Dictionary<string, object> Tags
        {
            get { return null; }
        }

        class FirstStep : PendingStep
        {
            private readonly Func<string, IPlainUser> _fetchUser;

            public FirstStep(Func<string, IPlainUser> fetchUser)
            {
                if (fetchUser == null)
                    throw new ArgumentNullException("fetchUser");

                _fetchUser = fetchUser;

                BytesToSend = null;
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                if (bytesReceived == null)
                    return Reject;

                var parts = Encoding.UTF8.GetString(bytesReceived).Split('\0');
                if (parts.Length != 3 || string.IsNullOrEmpty(parts[1]))
                    return Reject;

                var authorizationId = string.IsNullOrWhiteSpace(parts[0]) ? null : parts[0];
                var userName = parts[1];
                var password = string.IsNullOrWhiteSpace(parts[2]) ? null : parts[2];

                var user = _fetchUser(userName);
                if (user == null)
                    return Reject;

                if (user.Password != password)
                    return Reject;

                return Accept;
            }
        }    
    }
}
