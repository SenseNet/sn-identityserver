using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SenseNet.Extensions.DependencyInjection;
using SenseNet.IdentityServer4.Configuration;

namespace SenseNet.IdentityServer4.Tests
{
    [TestClass]
    public class EmailSenderTests
    {
        //[TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public async Task EmailSender_Empty()
        {
            var services = BuildServiceProvider();
            var emailSender = services.GetRequiredService<IEmailSender>();

            // empty parameters
            await emailSender.SendAsync(string.Empty, string.Empty, string.Empty, string.Empty);
        }

        //[TestMethod]
        public async Task EmailSender_MultipleEmails()
        {
            var services = BuildServiceProvider();
            var emailSender = services.GetRequiredService<IEmailSender>();

            //TODO: provide multiple email addresses
            await emailSender.SendAsync("", "Admin", "test subject", "test body");
        }

        private ServiceProvider BuildServiceProvider()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", true)
                .AddUserSecrets("c251710b-e98c-412f-b251-6ed6c01e9d4b")
                .AddEnvironmentVariables()
                .Build();
            var services = new ServiceCollection();

            services
                .AddLogging(cfg => cfg.AddConsole())
                .AddSingleton(configuration)
                .AddSnIdentityServerServices()

                .Configure<EmailSettings>(configuration.GetSection("sensenet:Email"));

            return services.BuildServiceProvider();
        }
    }
}
