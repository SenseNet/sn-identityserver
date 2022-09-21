using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SenseNet.IdentityServer4.Tests
{
    [TestClass]
    public class ClientStoreTests
    {
        //UNDONE: adding clients in test methods
        //[TestMethod]
        [ExpectedException(typeof(NotImplementedException))]
        public async Task ClientStore_AddClient()
        {
            var cs = new SnClientStore(null, null, null);
            var client = await cs.FindClientByIdAsync("abc");

            Assert.IsNull(client);

            // currently this method does not do anything
            cs.AddClient("abc");

            client = await cs.FindClientByIdAsync("abc");

            Assert.AreEqual("abc", client.ClientId);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public async Task ClientStore_GetClient_Invalid()
        {
            var cs = new SnClientStore(null, null, null);
            await cs.FindClientByIdAsync(null);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ClientStore_AddClient_Invalid_ClientId()
        {
            var cs = new SnClientStore(null, null, null);
            cs.AddClient(null);
        }
    }
}
