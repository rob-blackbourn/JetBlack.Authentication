namespace JetBlack.Authentication.Test
{
    public class MechanismFixture
    {
        protected const string AuthorizationId = null;
        protected const string Username = "tim";
        protected const string Password = "tanstaaftanstaaf";
        protected const string Hostname = "postoffice.reston.mci.net";

        public AuthenticationState GenericTest(ISaslMechanism client, ISaslMechanism server)
        {
            return GenericTest(client.InitialStep, server.InitialStep);
        }

        public AuthenticationState GenericTest(ISaslStep clientStep, ISaslStep serverStep)
        {
            if (clientStep.BytesToSend != null)
                serverStep = serverStep.Next(clientStep.BytesToSend);

            while (clientStep.State == AuthenticationState.Pending && serverStep.State == AuthenticationState.Pending)
            {
                clientStep = clientStep.Next(serverStep.BytesToSend);
                serverStep = serverStep.Next(clientStep.BytesToSend);
            }

            return serverStep.State;
        }
    }
}
