namespace JetBlack.Authentication.Mechanisms
{
    public abstract class Plain : ISaslMechanism
    {
        protected Plain(ISaslStep initialStep)
        {
            InitialStep = initialStep;
        }

        public string Name
        {
            get { return "PLAIN"; }
        }

        public ISaslStep InitialStep { get; private set; }    }
}
