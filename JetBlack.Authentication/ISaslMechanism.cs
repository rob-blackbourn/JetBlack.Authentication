namespace JetBlack.Authentication
{
    public interface ISaslMechanism
    {
        string Name { get; }
        ISaslStep InitialStep { get; }
    }
}
