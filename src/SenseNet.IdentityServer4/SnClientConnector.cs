using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using SenseNet.Client;
using SenseNet.Tools;

namespace SenseNet.IdentityServer4
{
    /// <summary>
    /// Responsible for handling identity-related operations on a remote service.
    /// </summary>
    public class SnClientConnector
    {
        public readonly ILogger Logger;
        private readonly IMailingListManager _mailingListManager;

        public ServerContext Server { get; }
        
        private static readonly string[] CommonUserFields = { "Id", "Name", "Path", "Type", "LoginName", "Email", "FullName", 
            "SyncGuid", "AgreedToTermsOfUse", "Enabled" };

        public SnClientConnector(ServerContext server, IMailingListManager mailingListManager, ILogger logger = null)
        {
            Server = server ?? throw new ArgumentNullException(nameof(server));
            Logger = logger;
            _mailingListManager = mailingListManager;
        }
        
        public async Task<SnUser> ValidateCredentialsAsync(string userName, string password)
        {
            // check if the repository is in the white list of accepted hosts
            if (!SnClientStore.IsAllowedRepository(Server.Url))
                return null;

            var request = new ODataRequest(Server)
            {
                ActionName = "ValidateCredentials",
                Path = "/Root"
            };

            try
            {
                var response = await RESTCaller.GetResponseJsonAsync(request, Server, HttpMethod.Post, new
                {
                    userName,
                    password
                }).ConfigureAwait(false);

                // we have to load the full user object because the method above returns only a couple of fields
                dynamic user = await Content.LoadAsync((int) response.id, Server).ConfigureAwait(false);

                return SnUser.FromClientContent(user);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, "Error during validate credentials request. Url: {0}", Server.Url);
            }

            return null;
        }

        public async Task SetAgreeToTermsAsync(SnUser user, bool agree = true, string token = null, bool enable = true)
        {
            try
            {
                Logger.LogTrace($"Setting Agree to terms flag on user {user.Email} with token '{token}' " +
                                 $"to {agree} and Enabled to {enable} in repository {Server.Url}");

                var userContent = Content.Create(user.Id, Server);
                userContent.Name = user.Name;
                userContent["AgreedToTermsOfUse"] = agree;
                userContent["SyncGuid"] = token ?? string.Empty;
                userContent["Enabled"] = enable;

                await userContent.SaveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, $"Could not set Agree to terms field on user {user.Username} in repo {Server.Url}");
            }
        }
        public async Task<SnUser> GetUserByProviderAsync(string provider, string userId)
        {            
            try
            {
                dynamic user = (await Content.QueryForAdminAsync($"TypeIs:User AND ExternalUserProviders:{provider}#Id#{userId}", 
                    select: CommonUserFields, server: Server)).FirstOrDefault();

                return user == null ? null : SnUser.FromClientContent(user);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, "Error during get user by provider request. " +
                                      $"Url: {Server.Url}, Provider: {provider}, userid: {userId}");
            }

            return null;
        }                     
        public async Task<SnUser> CreateUserAsync(string provider, string userId, IEnumerable<Claim> claims)
        {
            var request = new ODataRequest(Server)
            { 
                ActionName = "CreateUserByProvider",
                Path = "/Root",
                Select = CommonUserFields
            };

            //UNDONE: check Claim properties to serialize.
            // Currently only the Type and Value properties are sent.
            var claimsValue = JsonConvert.SerializeObject(claims.Select(cl => new ClaimInfo(cl)).ToArray());

            // The response is a dynamic object containing a single 'd' property
            // that wraps the actual user.
            dynamic user;
            try
            {
                dynamic response = await RESTCaller.GetResponseJsonAsync(request, Server, HttpMethod.Post, new
                {
                    provider,
                    userId,
                    claims = claimsValue
                }).ConfigureAwait(false);

                user = response.d;
            }
            catch (ClientException ex)
            {
                Logger.LogError($"EXT: Connector: user creation error: {ex.Message}");
                throw GetRegistrationException(ex);
            }
            catch (Exception ex)
            {
                Logger.LogError($"EXT: Connector: user creation error: {ex.Message}");
                throw new RegistrationException(RegistrationError.ServiceNotAvailable, ex);
            }

            var snUser = SnUser.FromClientContent(user);

            await _mailingListManager.Subscribe(snUser);

            return snUser;
        }

        public async Task<SnUser> CreateLocalUserAsync(string loginName, string password, string email)
        {
            //TODO: consider a cleanup logic for cases when the user content is created
            // but the registration process fails and the content remains in a half-state.

            var request = new ODataRequest(Server)
            {
                ActionName = "CreateLocalUser",
                Path = "/Root",
                Select = CommonUserFields
            };
            
            dynamic user;

            try
            {
                // The response is a dynamic object containing a single 'd' property
                // that wraps the actual user.
                dynamic response = await RESTCaller.GetResponseJsonAsync(request, Server, HttpMethod.Post, new
                {
                    loginName,
                    password,
                    email
                }).ConfigureAwait(false);
                user = response.d;
            }
            catch (ClientException ex)
            {
                throw GetRegistrationException(ex);
            }
            catch (Exception ex)
            {
                throw new RegistrationException(RegistrationError.ServiceNotAvailable, ex);
            }

            // set registration-specific fields and save them
            int userId = user.Id;
            var guid = Guid.NewGuid().ToString();
            var userContent = Content.Create(userId, Server);
            userContent.Name = user.Name;
            userContent["Enabled"] = false;
            userContent["SyncGuid"] = guid;

            try
            {
                await userContent.SaveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                //UNDONE: cleanup user or provide a meaningful message to the user.
                // Also check possible security issues with a user in a half-state.

                // We do not throw an exception here, because the user was successfully created
                // and can be repaired later by an administrator.
                Logger?.LogError(ex, "Error during registration: Enabled and Sync guid could not be saved " +
                                      $"for user {user.Name} ({user.Id}) to repository {Server.Url}");
            }

            var snUser = SnUser.FromClientContent(userContent);

            await _mailingListManager.Subscribe(snUser);

            return snUser;
        }

        private static RegistrationException GetRegistrationException(ClientException ex)
        {
            // parse error message and determine error type
            if (ex.Message?.Contains("There is already a user or group") ?? false)
                return new RegistrationException(RegistrationError.ExistingUser, ex);

            return ex.ErrorData.ExceptionType switch
            {
                "InvalidContentException" => new RegistrationException(RegistrationError.InvalidContent, ex),
                "LimitExceededException" => new RegistrationException(RegistrationError.LimitExceeded, ex),
                _ => new RegistrationException(RegistrationError.ServiceNotAvailable, ex),
            };
        }

        public async Task<SnUser> GetUserByTokenAsync(string token)
        {
            try
            {
                Logger.LogTrace($"Loading user by token {token} from repository {Server.Url}");

                //UNDONE: add expiration window to the query
                // For example based on the creation date of the user.
                dynamic user = await QueryUserByTokenAsync(token).ConfigureAwait(false);
                return user == null ? null : SnUser.FromClientContent(user);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, $"Error during finding user by token. Url: {Server.Url}, token: {token}");
            }

            return null;
        }
        public async Task<SnUser> EnableUserByTokenAsync(string token)
        {
            try
            {
                dynamic user = await QueryUserByTokenAsync(token).ConfigureAwait(false);
                if (user == null)
                {
                    Logger.LogWarning($"User not found in repository {Server.Url} by token {token}.");
                    return null;
                }

                // cleanup: enable user and remove token
                user["Enabled"] = true;
                user["SyncGuid"] = string.Empty;
                await user.SaveAsync();

                return SnUser.FromClientContent(user);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, $"Error during confirming user by token. Url: {Server.Url}, token: {token}");
            }

            return null;
        }

        public async Task SetTokenAsync(SnUser user, string token)
        {
            try
            {
                Logger.LogTrace($"Saving token {token} on user {user.Username} in repository {Server.Url}");

                var userContent = Content.Create(user.Id, Server);
                userContent.Name = user.Name;
                userContent["SyncGuid"] = token;
                await userContent.SaveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, $"Error during setting sync guid for user {user.Username} in repository {Server.Url}");
            }
        }

        public async Task<SnUser> SetPasswordByTokenAsync(string token, string password)
        {
            try
            {
                dynamic user = await QueryUserByTokenAsync(token).ConfigureAwait(false);
                if (user == null)
                    return null;

                // cleanup: enable user and remove token
                user["Enabled"] = true;
                user["SyncGuid"] = string.Empty;
                user["Password"] = password;

                await user.SaveAsync();

                return SnUser.FromClientContent(user);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, $"Error during setting password by token. Url: {Server.Url}, token: {token}");
            }

            return null;
        }

        public async Task SendChangePasswordMailAsync(string email, string returnUrl)
        {
            var request = new ODataRequest(Server)
            {
                ActionName = "SendChangePasswordMail",
                Path = "/Root"
            }; 
            try
            {
                dynamic response = await RESTCaller.GetResponseJsonAsync(request, Server, HttpMethod.Post, new
                {
                    email,
                    returnUrl
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger?.LogError(ex, $"Error during sending change password mail. Url: {Server.Url}, email: {email}");
            }
        }

        /// <summary>
        /// Checks if the provided user is a member or all the provided groups.
        /// </summary>
        /// <param name="userId">User content id.</param>
        /// <param name="groups">Group Path list.</param>
        public async Task<bool> IsInGroup(int userId, string[] groups)
        {
            if (groups == null || groups.Length == 0)
                return true;
            
            var rolePaths = await Retrier.RetryAsync(3, 500, async () =>
            {
                // collect all roles of the user in a path array
                return (await Content.LoadReferencesAsync(userId, "AllRoles", new[] {"Id", "Path", "Name"}, Server)
                        .ConfigureAwait(false))
                    .Select(c => c.Path).ToArray();
            }, (strings, retryCount, ex) =>
            {
                // no error, no problem
                if (ex == null) 
                    return true;

                // log only once
                if (retryCount == 3)
                    Logger.LogError(ex,$"Error during loading groups of user {userId} from {Server.Url}");

                return false;
            }).ConfigureAwait(false) ?? Array.Empty<string>();

            return groups.All(rolePaths.Contains);
        }

        private async Task<Content> QueryUserByTokenAsync(string token)
        {
            //UNDONE: add expiration window to the query
            // For example based on the creation date of the user.
            return (await Content.QueryForAdminAsync($"TypeIs:User AND SyncGuid:'{token}'",
                select: CommonUserFields, server: Server)).FirstOrDefault();
        }
    }
}
