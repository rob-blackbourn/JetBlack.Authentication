using JetBlack.Authentication.Mechanisms;
using NUnit.Framework;

namespace JetBlack.Authentication.Test.Mechanisms
{
    [TestFixture]
    public class CramMd5Fixture : MechanismFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new CramMd5Client(Username, Password);
            var server = new CramMd5Server(_ => new CramMd5User(Username, Password), Hostname);

            var state = GenericTest(client, server);

            Assert.AreEqual(AuthenticationState.Accepted, state);
        }
    }

    class CramMd5User : ICramMd5User
    {
        public CramMd5User(string userName, string password)
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
