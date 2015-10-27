using System;
using System.Text;

namespace JetBlack.Authentication.Mechanisms
{
    public class PlainClient : Plain
    {
        public PlainClient(string authorizationId, string userName, string password)
            : base(new FirstStep(authorizationId, userName, password))
        {
        }

        class FirstStep : PendingStep
        {
            public FirstStep(string authorizationId, string userName, string password)
            {
                if (string.IsNullOrEmpty(userName))
                    throw new ArgumentException("Argument 'username' value must be specified.", "userName");
                if (password == null)
                    throw new ArgumentNullException("password");

                BytesToSend = Encoding.UTF8.GetBytes(string.Concat(authorizationId ?? string.Empty, '\0', userName, '\0', password));
            }

            public override ISaslStep Next(byte[] bytesReceived)
            {
                return Accept;
            }
        }
    }
}
