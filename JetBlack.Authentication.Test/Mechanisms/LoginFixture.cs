using JetBlack.Authentication.Mechanisms;
using NUnit.Framework;

namespace JetBlack.Authentication.Test.Mechanisms
{
    [TestFixture]
    public class LoginFixture : MechanismFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new LoginClient(Username, Password);
            var server = new LoginServer(_ => new LoginUser(Username, Password));

            var state = GenericTest(client, server);

            Assert.AreEqual(AuthenticationState.Accepted, state);
        }
    }

    class LoginUser : ILoginUser
    {
        public LoginUser(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        public string UserName { get; private set; }
        public string Password { get; private set; }
    }
}
