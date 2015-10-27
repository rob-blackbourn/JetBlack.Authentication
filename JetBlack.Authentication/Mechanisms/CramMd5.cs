namespace JetBlack.Authentication.Mechanisms
{
    public abstract class CramMd5 : ISaslMechanism
    {
        protected CramMd5(ISaslStep initialStep)
        {
            InitialStep = initialStep;
        }

        public string Name
        {
            get { return "CRAM-MD5"; }
        }

        public ISaslStep InitialStep { get; private set; }
    }
}
