using System;

namespace JetBlack.Authentication.Mechanisms
{
    internal class AcceptStep : ISaslStep
    {
        public AcceptStep()
            : this(null)
        {
        }

        public AcceptStep(byte[] bytesToSend)
        {
            BytesToSend = bytesToSend;
        }

        public AuthenticationState State { get { return AuthenticationState.Accepted; } }

        public byte[] BytesToSend { get; private set; }

        public ISaslStep Next(byte[] bytesReceived)
        {
            throw new NotImplementedException();
        }
    }
}
