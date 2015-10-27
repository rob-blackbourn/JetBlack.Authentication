namespace JetBlack.Authentication.Mechanisms
{
    internal abstract class PendingStep : ISaslStep
    {
        public AuthenticationState State { get { return AuthenticationState.Pending; } }

        public byte[] BytesToSend { get; protected set; }

        public abstract ISaslStep Next(byte[] bytesReceived);

        public static ISaslStep Reject = new RejectStep();
        public static ISaslStep Accept = new AcceptStep();
    }
}
