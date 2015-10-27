using System;
using System.Security.Cryptography;
using JetBlack.Authentication.Mechanisms;
using NUnit.Framework;

namespace JetBlack.Authentication.Test.Mechanisms
{
    [TestFixture]
    public class ScramSha1Fixture : MechanismFixture
    {
        [Test]
        public void SmokeTest()
        {
            const string userName = "user";
            const string password = "pencil";
            Func<string> clientNonceGenerator = () => "fyko+d2lbbFgONRv9qkxdawL";
            Func<string> serverNonceGenerator = () => "3rfcNHYJY1ZVvWVs7j";
            const string salt = "QSXCR+Q6sek8bf92";
            const int iterations = 4096;
            var saltedPassword = Convert.ToBase64String(new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), iterations).GetBytes(20));

            var client = new ScramSha1Client(userName, password, clientNonceGenerator);
            var server = new ScramSha1Server(_ => new ScramSha1User(userName, saltedPassword, salt, iterations), serverNonceGenerator);

            var state = GenericTest(client, server);

            Assert.AreEqual(AuthenticationState.Accepted, state);
        }
    }

    class ScramSha1User : IScramSha1User
    {
        public ScramSha1User(string userName, string saltedPassword, string salt, int iterations)
        {
            UserName = userName;
            SaltedPassword = saltedPassword;
            Salt = salt;
            Iterations = iterations;
        }

        public string UserName { get; private set; }
        public string SaltedPassword { get; private set; }
        public string Salt { get; private set; }
        public int Iterations { get; private set; }
    }
}
