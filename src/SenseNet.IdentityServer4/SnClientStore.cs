using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SenseNet.Client;
using SenseNet.Diagnostics;
using IS4=IdentityServer4.Models;

namespace SenseNet.IdentityServer4
{
    public class SnClientStore : IClientStore
    {
        //UNDONE: find a way to implement a singleton clientstore
        // Currently the client store is registered as Transient, so we cannot
        // store data in the instance :(.
        protected static readonly ConcurrentDictionary<string, IS4.Client> ClientCache = new();
        protected static readonly ConcurrentDictionary<string, string> InternalClientIdsByRepository = new();
        protected static readonly ConcurrentDictionary<string, string> RepositoriesByClientId = new();
        public static readonly ConcurrentDictionary<string, string> RealRepositoryUrls = new();
        public static readonly ConcurrentBag<string> AllowedRepositories = new();

        protected readonly IdentityServerTools IsTools;
        protected readonly IConfiguration Config;
        protected readonly ILogger<SnClientStore> Logger;
        protected static readonly SemaphoreSlim ClientSemaphore = new(1);

        private readonly bool _setDefaultClients;
        private bool _defaultClientsLoaded;

        //============================================================================= Constructors

        public SnClientStore(IdentityServerTools identityServerTools, IConfiguration config, ILogger<SnClientStore> logger)
        {
            IsTools = identityServerTools;
            Config = config;
            Logger = logger;
            _setDefaultClients = Config.GetValue<bool>("sensenet:Authentication:SetDefaultClients");
        }

        //============================================================================= Public API

        public bool AddClient(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));

            SnTrace.System.Write($"Adding client {clientId}");

            //UNDONE: check which type of client should we add here (js? mvc?)
            //return ClientCache.TryAdd(clientId, GetClient(clientId));
            return true;
        }

        public virtual async Task<IS4.Client> FindClientByIdAsync(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));

            if (ClientCache.TryGetValue(clientId, out var client))
            {
                // make sure we know the repository of this client
                if (RepositoriesByClientId.ContainsKey(clientId))
                    return client;

                Logger?.LogWarning($"Repository info is missing for client {clientId}. Reloading clients.");
            }
            else
            {
                Logger?.LogTrace($"Client {clientId} not found in cache.");
            }

            await ClientSemaphore.WaitAsync();

            try
            {
                if (_setDefaultClients && !_defaultClientsLoaded)
                {
                    SetDefaultClients();
                }

                // try again, maybe it was loaded on another thread
                if (ClientCache.TryGetValue(clientId, out client))
                    return client;
                
                await LoadClientsFromRepositories().ConfigureAwait(false);

                // try again
                if (ClientCache.TryGetValue(clientId, out client))
                    return client;
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, "Error during loading clients.");
            }
            finally
            {
                ClientSemaphore.Release();
            }

            return client;
        }

        protected void RegisterClient(string clientId, Repository[] repoHosts, bool internalClient)
        {
            if (repoHosts == null || !repoHosts.Any())
            {
                Logger.LogWarning($"No repository host is defined for clientid {clientId}");
                return;
            }

            Logger.LogTrace($"Registering client {clientId}. Internal: {internalClient}. " +
                             $"Repositories: {string.Join(", ", repoHosts.Select(rh => rh.ToString()))}");

            if (internalClient)
            {
                foreach (var repository in repoHosts)
                {
                    InternalClientIdsByRepository[repository.PublicHost.TrimSchema()] = clientId;
                }
            }
            
            foreach (var repository in repoHosts)
            {
                var publicHost = repository.PublicHost.TrimSchema();
                var internalHost = repository.InternalHost.TrimSchema();

                RepositoriesByClientId.TryAdd(clientId ?? string.Empty, publicHost);

                // Collect public-internal url pairs so that we can use the appropriate
                // url internally when connecting to the repository. This is necessary
                // in a containerized environment, where public and internal host names
                // may be different.
                // Note that the key is the host (no schema!) but the value must contain
                // the originally configured value.
                RealRepositoryUrls.TryAdd(publicHost, string.IsNullOrEmpty(repository.InternalHost) 
                    ? repository.PublicHost : repository.InternalHost);

                // Cache the repo url itself for validating repositories that want to 
                // authenticate through this identity server.
                if (!AllowedRepositories.Contains(publicHost))
                    AllowedRepositories.Add(publicHost);
                if (!AllowedRepositories.Contains(internalHost))
                    AllowedRepositories.Add(internalHost);
            }
        }

        /// <summary>
        /// Gets a system client id for a repository. We can generate a temporary token
        /// for this client id using IdentityServerTools.
        /// </summary>
        /// <param name="repository">Repository host or url.</param>
        /// <returns>A cached client id or the default "client".</returns>
        public static string GetInternalClientId(string repository)
        {
            return InternalClientIdsByRepository.TryGetValue(repository?.TrimSchema() ?? string.Empty, out var clientId)
                ? clientId
                : "client";
        }

        /// <summary>
        /// Gets the real url based on the repository url. This is required on case of a containerized environment
        /// when we have to translate the public repository url to an internal container-specific url.
        /// </summary>
        /// <param name="repoUrl">Repository url</param>
        /// <returns>The related internal url or itself in case it is not found.</returns>
        public static string GetRealUrl(string repoUrl)
        {
            if (string.IsNullOrEmpty(repoUrl))
                return repoUrl;

            return RealRepositoryUrls.TryGetValue(repoUrl.TrimSchema().TrimEnd('/', ' '),
                out var realUrl)
                ? realUrl.AppendSchema().TrimEnd('/', ' ')
                : repoUrl.AppendSchema().TrimEnd('/', ' ');
        }

        public static bool IsAllowedRepository(string repository)
        {
            return !string.IsNullOrEmpty(repository) && AllowedRepositories.Contains(repository.TrimSchema());
        }

        //============================================================================= Helper methods

        //UNDONE: remove default clients when the central service can provide clients
        public void SetDefaultClients()
        {
            Logger.LogTrace("Loading configured clients.");

            var clientConfig = Config.GetSection("sensenet:Clients");
            if (clientConfig == null)
                return;

            foreach (var clientSection in clientConfig.GetChildren())
            {
                var clientId = clientSection.Key;
                var client = new SnClient { ClientId = clientId };

                // load properties from configuration
                clientConfig.GetSection(clientId).Bind(client);

                // if this is a client that allows authenticating using a secret (usually tools)
                if (client.AllowedGrantTypes.Contains(GrantType.ClientCredentials))
                {
                    // set default secret if not provided in config
                    var secret = client.ClientSecrets.FirstOrDefault();
                    if (secret == null)
                        client.ClientSecrets.Add(secret = new Secret());

                    // encode configured or default secret value
                    var secretValue = secret.Value;
                    secret.Value = string.IsNullOrEmpty(secretValue) ? "secret".Sha256() : secretValue.Sha256();

                    Logger.LogTrace($"Secret loaded from config for client {clientId}: {secretValue?.Truncate(5)}... " +
                                     $"Encoded: {secret.Value?.Truncate(5)}...");

                    // set sensenet user id for client tools
                    if (client.UserId > 0)
                    {
                        client.Claims = new[] { new Claim(JwtClaimTypes.Subject, client.UserId.ToString()) };
                    }
                    else if (!string.IsNullOrEmpty(client.UserName))
                    {
                        client.Claims = new[] { new Claim(JwtClaimTypes.Subject, client.UserName) };
                    }
                }
                
                ClientCache.AddOrUpdate(clientId, client, (_, _) => client);

                RegisterClient(clientId, client.RepositoryHosts, client.InternalClient);
            }

            _defaultClientsLoaded = true;
        }

        private async Task LoadClientsFromRepositories()
        {
            Logger.LogTrace("Loading clients from configured repositories");

            var clientConfig = Config.GetSection("sensenet:Clients");
            if (clientConfig == null)
                return;

            var configuredRepositories = new List<string>();

            // collect all repository urls from configured clients
            foreach (var clientSection in clientConfig.GetChildren())
            {
                var clientId = clientSection.Key;
                var client = new SnClient { ClientId = clientId };

                // load properties from configuration
                clientSection.Bind(client);

                if (client.RepositoryHosts == null) 
                    continue;

                foreach (var repository in client.RepositoryHosts)
                {
                    // we have to collect the real url that we can use to connect to the repository
                    var hostUrl = string.IsNullOrEmpty(repository.InternalHost)
                        ? repository.PublicHost
                        : repository.InternalHost;

                    if (!configuredRepositories.Contains(hostUrl))
                        configuredRepositories.Add(hostUrl);
                }
            }

            // iterate through all well-known repositories and load clients from their databases
            foreach (var repository in configuredRepositories)
            {
                Logger.LogTrace($"Loading clients from {repository}");

                var server = new ServerContext
                {
                    Url = repository.AppendSchema(),
                    IsTrusted = true,
                    Authentication =
                    {
                        //TODO: check if a hardcoded client id is acceptable
                        AccessToken = await IsTools.GetClientJwtAsync("client").ConfigureAwait(false)
                    }
                };

                var connector = new SnClientConnector(server, null, Logger);
                var clients = await connector.GetClientsAsync().ConfigureAwait(false);

                foreach (var client in clients)
                {
                    // load additional properties from configuration
                    AddClientByTemplate(client);

                    RegisterClient(client.ClientId, new[]
                        {
                            new Repository
                            {
                                PublicHost = client.Repository.TrimSchema(),
                                InternalHost = repository.TrimSchema()
                            }
                        },
                        client.Type == ClientType.InternalClient);
                }
            }
        }

        protected SnClient AddClientByTemplate(ClientInfo clientInfo)
        {
            // find the appropriate template name for this client
            var clientTemplateName = clientInfo.Type switch
            {
                ClientType.ExternalClient => "client",
                ClientType.InternalClient => "client",
                ClientType.AdminUi => "adminui",
                ClientType.ExternalSpa => "spa",
                ClientType.InternalSpa => "spa",
                _ => throw new NotImplementedException($"{clientInfo.Type} client type is not handled.")
            };

            Logger.LogTrace($"Adding client {clientInfo.ClientId} with template {clientTemplateName}");

            var clientConfig = Config.GetSection("sensenet:Clients:" + clientTemplateName);
            if (clientConfig == null)
            {
                Logger.LogWarning($"Client template {clientTemplateName} not found");
                return null;
            }

            var client = new SnClient { ClientId = clientInfo.ClientId };

            // load properties from configuration
            clientConfig.Bind(client);

            // if this is a client that allows authenticating using a secret (usually tools)
            if (client.AllowedGrantTypes.Contains(GrantType.ClientCredentials))
            {
                Logger.LogTrace($"Loading secrets for client {clientInfo.ClientId}.");

                // remove empty secrets for security reasons: we do not want to use the default secret anymore
                var emptySecrets = client.ClientSecrets.Where(s => string.IsNullOrEmpty(s.Value)).ToList();
                foreach (var emptySecret in emptySecrets)
                {
                    client.ClientSecrets.Remove(emptySecret);
                }

                if (clientInfo.Secrets != null)
                {
                    // set dynamic secrets
                    foreach (var secretInfo in clientInfo.Secrets.Where(si => si.ValidTill > DateTime.UtcNow))
                    {
                        var secretValue = secretInfo.Value;

                        if (!string.IsNullOrEmpty(secretValue))
                        {
                            Logger.LogTrace($"Registering secret {secretValue.Substring(0, 5)} " +
                                            $"(valid till {secretInfo.ValidTill}) for client {clientInfo.ClientId}.");

                            client.ClientSecrets.Add(new Secret(secretValue.Sha256(), secretInfo.ValidTill));
                        }
                        else
                        {
                            Logger.LogTrace($"Secret {secretInfo.Id} is empty for client {clientInfo.ClientId}.");
                        }
                    }
                }
                else
                {
                    Logger.LogTrace($"Secret list is empty for client {clientInfo.ClientId}.");
                }
                
                // see if a user is set in the info object or in config
                var userName = string.IsNullOrEmpty(clientInfo.UserName)
                    ? client.UserName
                    : clientInfo.UserName;

                // set sensenet user id for client tools
                if (client.UserId > 0)
                {
                    client.Claims = new[] { new Claim(JwtClaimTypes.Subject, client.UserId.ToString()) };
                }

                if (!string.IsNullOrEmpty(userName))
                {
                    client.Claims = new[] { new Claim(JwtClaimTypes.Subject, userName) };
                }
            }

            ClientCache.AddOrUpdate(client.ClientId, client, (_, _) => client);

            return client;
        }
    }
}
