using System;
using System.Collections.Generic;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public interface ILoginUser
    {
        string UserName { get; }
        string Password { get; }
    }

    public class LoginServer : Login
    {
        public LoginServer(Func<string,ILoginUser> fetchUser )
            : base(new FirstStep(fetchUser))
        {
        }

        public Dictionary<string, object> Tags { get { return null; } }

        class FirstStep : PendingStep
        {
            private readonly Func<string, ILoginUser> _fetchUser;

            public FirstStep(Func<string, ILoginUser> fetchUser)
            {
                _fetchUser = fetchUser;
                BytesToSend = Encoding.ASCII.GetBytes("UserName:");
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                var userName = Encoding.UTF8.GetString(bytesReceived);
                return new SecondStep(userName, _fetchUser);
            }
        }

        class SecondStep : PendingStep
        {
            private readonly string _userName;
            private readonly Func<string, ILoginUser> _fetchUser;

            public SecondStep(string userName, Func<string, ILoginUser> fetchUser)
            {
                _userName = userName;
                _fetchUser = fetchUser;
                BytesToSend = Encoding.ASCII.GetBytes("Password:");
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                if (bytesReceived == null)
                    return Reject;

                var password = Encoding.UTF8.GetString(bytesReceived);

                var user = _fetchUser(_userName);
                if (user == null)
                    return Reject;

                if (password != user.Password)
                    return Reject;

                return Accept;
            }
        }
    }
}
