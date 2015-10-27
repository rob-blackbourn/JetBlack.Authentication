using System;

namespace JetBlack.Authentication.Mechanisms
{
    internal class RejectStep : ISaslStep
    {
        public AuthenticationState State { get { return AuthenticationState.Rejected; } }

        public byte[] BytesToSend { get { return null; } }

        public ISaslStep Next(byte[] bytesReceived)
        {
            throw new NotImplementedException();
        }
    }
}
