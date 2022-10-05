using System;
using System.Threading.Tasks;
using IdentityServer4;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SenseNet.Client;
using SenseNet.Client.Authentication;

namespace SenseNet.IdentityServer4
{
    public class SnClientConnectorFactory
    {
        protected readonly IWebHostEnvironment WebHostEnvironment;
        protected readonly ILogger<SnClientConnector> Logger;
        protected readonly IdentityServerTools IsTools;
        protected readonly IMailingListManager MailingListManager;
        protected readonly ITokenStore TokenStore;
        protected readonly ITokenProvider TokenProvider;

        public SnClientConnectorFactory(IWebHostEnvironment webHostEnvironment, IdentityServerTools identityServerTools,
            ILogger<SnClientConnector> logger, IMailingListManager mailingListManager,
            ITokenStore tokenStore, ITokenProvider tokenProvider)
        {
            WebHostEnvironment = webHostEnvironment;
            IsTools = identityServerTools;
            Logger = logger;
            MailingListManager = mailingListManager;
            TokenStore = tokenStore;
            TokenProvider = tokenProvider;
        }

        /// <summary>
        /// Assembles a client connector containing a server object that points to the repository
        /// url found in the provided return url.
        /// For authentication we create a special access token based on the repo url so that
        /// we skip the roundtrip this IdentityServer for a valid token.
        /// </summary>
        public async Task<SnClientConnector> CreateAsync(string returnUrl)
        {
            // Assume this is a return url containing the repo url. If it is not recognizable,
            // use it as a repository url.
            var repoUrl = IdentityTools.GetRepositoryUrl(returnUrl);
            if (string.IsNullOrEmpty(repoUrl))
                repoUrl = returnUrl;
            var clientId = SnClientStore.GetInternalClientId(repoUrl);
            if (string.IsNullOrEmpty(clientId))
            {
                Logger.LogWarning("Unknown repository: " + repoUrl);
                throw new InvalidOperationException("Unknown repository");
            }

            var realRepoUrl = SnClientStore.GetRealUrl(repoUrl);

            Logger.LogTrace($"Creating client connector for {realRepoUrl} with clientid {clientId}");

            var authToken = await IsTools.GetClientJwtAsync(clientId).ConfigureAwait(false);

            return CreateConnector(realRepoUrl, authToken);
        }

        public SnClientConnector CreateAsVisitor(string returnUrl)
        {
            // Assume this is a return url containing the repo url. If it is not recognizable,
            // use it as a repository url.
            var repoUrl = IdentityTools.GetRepositoryUrl(returnUrl);
            if (string.IsNullOrEmpty(repoUrl))
                repoUrl = returnUrl;

            var realRepoUrl = SnClientStore.GetRealUrl(repoUrl);

            Logger.LogTrace($"Creating client connector for {realRepoUrl} without authentication.");

            return CreateConnector(realRepoUrl, null);
        }

        private SnClientConnector CreateConnector(string repoUrl, string accessToken)
        {
            var server = new ServerContext
            {
                Url = repoUrl,
                IsTrusted = WebHostEnvironment.IsDevelopment(),
                Authentication =
                {
                    AccessToken = accessToken
                }
            };

            return new SnClientConnector(server, MailingListManager, Logger);
        }

        /// <summary>
        /// Assembles a client connector containing a server object that points to the repository
        /// url. Use this method when accessing a repository unrelated to this Identity Server.
        /// </summary>
        protected async Task<SnClientConnector> CreateAsync(string repoUrl, string clientId, string secret)
        {
            var server = new ServerContext
            {
                Url = SnClientStore.GetRealUrl(repoUrl),
                IsTrusted = WebHostEnvironment.IsDevelopment()
            };

            server.Authentication.AccessToken = await TokenStore.GetTokenAsync(server, clientId, secret)
                .ConfigureAwait(false);

            return new SnClientConnector(server, MailingListManager, Logger);
        }
    }
}
