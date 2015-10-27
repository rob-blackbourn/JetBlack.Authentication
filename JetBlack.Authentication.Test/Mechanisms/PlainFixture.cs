using JetBlack.Authentication.Mechanisms;
using NUnit.Framework;

namespace JetBlack.Authentication.Test.Mechanisms
{
    [TestFixture]
    public class PlainFixture : MechanismFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new PlainClient(AuthorizationId, Username, Password);
            var server = new PlainServer(_ => new PlainUser(Username, Password));

            var state = GenericTest(client, server);

            Assert.AreEqual(AuthenticationState.Accepted, state);
        }
    }

    class PlainUser : IPlainUser
    {
        public PlainUser(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        public string UserName { get; private set; }
        public string Password { get; private set; }
        public bool IsImpersonateable(string authenticationId)
        {
            return true;
        }
    }
}
