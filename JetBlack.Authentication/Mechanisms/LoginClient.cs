using System;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public class LoginClient : Login
    {
        public LoginClient(string userName, string password)
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
                    throw new ArgumentException("Argument 'username' value must be specified.", "userName");
                if (password == null)
                    throw new ArgumentNullException("password");

                _userName = userName;
                _password = password;

                BytesToSend = null;
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                if (bytesReceived != null && Encoding.UTF8.GetString(bytesReceived) == "UserName:")
                    return new SecondStep(_userName, _password);

                return Reject;
            }
        }

        class SecondStep : PendingStep
        {
            private readonly string _password;

            public SecondStep(string userName, string password)
            {
                _password = password;
                BytesToSend = Encoding.UTF8.GetBytes(userName);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                if (bytesReceived == null)
                    return Reject;

                var message = Encoding.UTF8.GetString(bytesReceived);
                if (message == "Password:")
                    return new ThirdStep(_password);

                return Reject;
            }
        }

        class ThirdStep : PendingStep
        {
            public ThirdStep(string password)
            {
                BytesToSend = Encoding.UTF8.GetBytes(password);
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                return new AcceptStep();
            }
        }
    }
}
