namespace JetBlack.Authentication.Mechanisms
{
    public abstract class Login : ISaslMechanism
    {
        protected Login(ISaslStep initialStep)
        {
            InitialStep = initialStep;
        }

        public string Name
        {
            get { return "LOGIN"; }
        }

        public ISaslStep InitialStep { get; private set; }
    }
}
