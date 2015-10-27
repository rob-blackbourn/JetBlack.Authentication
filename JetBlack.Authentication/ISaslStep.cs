namespace JetBlack.Authentication
{
    public interface ISaslStep
    {
        AuthenticationState State { get; }
        byte[] BytesToSend { get; }
        ISaslStep Next(byte[] bytesReceived);
    }
}
