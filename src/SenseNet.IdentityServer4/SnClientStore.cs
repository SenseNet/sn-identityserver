﻿using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
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
        
        protected readonly IConfiguration Config;
        protected readonly ILogger<SnClientStore> Logger;
        protected static readonly SemaphoreSlim ClientSemaphore = new(1);

        private readonly bool _setDefaultClients;
        private bool _defaultClientsLoaded;

        //============================================================================= Constructors

        public SnClientStore(IConfiguration config, ILogger<SnClientStore> logger)
        {
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

                ClientCache.TryAdd(clientId, client);

                RegisterClient(clientId, client.RepositoryHosts, client.InternalClient);
            }

            _defaultClientsLoaded = true;
        }
    }
}
