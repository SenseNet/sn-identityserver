using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SenseNet.IdentityServer4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Extensions.Options;
using SenseNet.IdentityServer4.Configuration;

namespace IdentityServer4.Quickstart.UI
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly ILogger<ExternalController> _logger;
        private readonly IEventService _events;
        private readonly IEmailSender _emailSender;
        private readonly ITemplateManager _templateManager;
        private readonly LoginPageOptions _loginOptions;
        private readonly NotificationOptions _notificationOptions;
        private readonly SnClientConnectorFactory _clientConnectorFactory;
        private readonly IRegistrationManager _registrationManager;

        public ExternalController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            ILogger<ExternalController> logger,
            IEmailSender emailSender,
            ITemplateManager templateManager,
            IOptions<LoginPageOptions> loginOptions,
            SnClientConnectorFactory clientConnectorFactory,
            IOptions<NotificationOptions> notificationOptions,
            IRegistrationManager registrationManager)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _logger = logger;
            _events = events;

            _emailSender = emailSender;
            _templateManager = templateManager;

            _loginOptions = loginOptions?.Value ?? new LoginPageOptions();
            _clientConnectorFactory = clientConnectorFactory;
            _notificationOptions = notificationOptions.Value;
            _registrationManager = registrationManager;
        }

        /// <summary>
        /// initiate roundtrip to external authentication provider
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Challenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }

            if (AccountOptions.WindowsAuthenticationSchemeName == provider)
            {
                // windows authentication needs special handling
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // start challenge and roundtrip the return URL and scheme 
                var props = new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Callback)),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", provider },
                    }
                };

                return Challenge(props, provider);
            }
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            _logger.LogTrace("EXT: Callback START");

            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                await SendRegistrationNotification(result, "External authentication failed.");

                _logger.LogError("EXT: External authentication error.");
                throw new Exception("External authentication error");
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                _logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            // check if this is an allowed repository
            var connector = await GetClientConnectorAsync(result).ConfigureAwait(false);
            if (!SnClientStore.IsAllowedRepository(connector.Server?.Url))
            {
                var repositoryList = SnClientStore.AllowedRepositories.Count > 20
                    ? "[more than 20]"
                    : string.Join(", ", SnClientStore.AllowedRepositories);
                _logger?.LogError($"Invalid repository: {connector.Server?.Url}. Allowed repositories: " + repositoryList);

                await SendRegistrationNotification(result, 
                    $"External authentication was successful, but the repository {connector.Server?.Url} is not allowed.");

                throw new Exception("Invalid repository for external authentication.");
            }

            _logger.LogTrace("EXT: Callback: searching for user.");

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProvider(result, connector);
            if (user == null)
            {
                // this might be where you might initiate a custom workflow for user registration
                // in this sample we don't show how that would be done, as our sample implementation
                // simply auto-provisions new external user

                // [sensenet] create user in the repository
                _logger.LogTrace("EXT: User not found, creating...");

                try
                {
                    //UNDONE: create users only if this feature is enabled
                    user = await connector.CreateUserAsync(provider, providerUserId, claims);

                    _logger.LogInformation("EXT: User created: " + user?.Username);

                    await SendRegistrationNotification(connector, user);
                }
                catch (RegistrationException rex)
                {
                    _logger?.LogWarning(rex, $"Error during user registration to {connector.Server?.Url}. Provider: {provider} UserId: {providerUserId}. {rex.Error}");

                    await SendRegistrationNotification(result, 
                        "External authentication was successful, but the user could not be created. " + rex.Message);

                    return RedirectToLogin(result, rex.Error);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, $"Error during user registration to {connector.Server?.Url}. Provider: {provider} UserId: {providerUserId}. {ex.Message}");

                    await SendRegistrationNotification(result,
                        "External authentication was successful, but the user could not be created. " + ex.Message);

                    // do not pass on the real error message to the GUI
                    throw new Exception("Error during registration.");
                }

                // New external user in snaas: redirect to the create repository page where the user will have to provide
                // a password to set for the first public admin user in the new repo.

                if (_registrationManager.ExternalRegistrationRedirectToPasswordForm(connector))
                {
                    //UNDONE: probably set return url here
                    return View("CreateRepository", new CreateRepositoryInputModel
                    {
                        Email = user?.Email
                    });
                }
            }

            // if the user has not agreed yet to the terms of use, redirect to the intermediate page
            if (_loginOptions.ForceAgreeTerms && !user.AgreedToTerms)
            {
                _logger.LogTrace($"Displaying Agree to terms page for user {user.Name} in repository {connector.Server?.Url}.");

                //UNDONE: probably set return url here
                return View("AgreeToTerms", new LoginViewModel());
            }

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            
            if (!await _clientStore.IsUserAllowedAsync(context?.ClientId, user.Id, connector).ConfigureAwait(false))
            {
                // registration was successful, but we cannot log in the user using this client
                _logger.LogWarning($"User {user.Name} is not allowed to log in using " +
                                   $"client id {context?.ClientId} to repository {connector.Server?.Url}.");

                return RedirectToLogin(result, RegistrationError.InvalidClientAfterRegistration);
            }

            _logger.LogTrace("EXT: Callback: Calling events...");

            // this allows us to collect any additional claims or properties
            // for the specific protocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            await HttpContext.SignInAsync(user.SubjectId, user.Username, provider, localSignInProps, additionalLocalClaims.ToArray());

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            
            // check if external login is in the context of an OIDC request
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.SubjectId, user.Username, true, context?.ClientId));

            _logger.LogTrace("EXT: Callback END");

            if (context != null)
            {
                if (await _clientStore.IsPkceClientAsync(context.ClientId))
                {
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("Redirect", new RedirectViewModel { RedirectUrl = returnUrl });
                }
            }

            return Redirect(returnUrl);
        }

        private async Task SendRegistrationNotification(AuthenticateResult result, Exception exception)
        {
            await SendRegistrationNotification(result, exception.Message);
        }
        private async Task SendRegistrationNotification(AuthenticateResult result, string errorMessage)
        {
            var userName = result?.Principal?.Identity?.Name ?? "unknown";
            var returnUrl = result?.Ticket?.Properties?.GetString("returnUrl") ?? string.Empty;
            var repoUrl = IdentityTools.GetRepositoryUrl(returnUrl);

            await SendRegistrationNotification("email.internal-registration-error", (subject, template) =>
            {
                template = template.Replace("{Username}", userName)
                    .Replace("{UserType}", "external user")
                    .Replace("{Email}", "unknown")
                    .Replace("{Repository}", repoUrl)
                    .Replace("{ErrorMessage}", errorMessage);

                return (subject, template);
            });
        }
        private async Task SendRegistrationNotification(SnClientConnector connector, SnUser user)
        {
            var repoUrl = connector?.Server?.Url;

            await SendRegistrationNotification("email.internal-registration-success", (subject, template) =>
            {
                template = template.Replace("{Username}", user.Username)
                    .Replace("{Email}", user.Email)
                    .Replace("{UserType}", "external user")
                    .Replace("{Repository}", repoUrl);

                return (subject, template);
            });
        }
        private async Task SendRegistrationNotification(string templateName, Func<string, string, (string, string)> editEmail)
        {
            if (string.IsNullOrEmpty(_notificationOptions.AdminEmail))
                return;

            try
            {
                var (subject, template) = await _templateManager.LoadAndFillEmailTemplateAsync(
                    templateName, null, HttpContext, null, null).ConfigureAwait(false);

                (subject, template) = editEmail(subject, template);

                await _emailSender.SendAsync(_notificationOptions.AdminEmail, "SNaaS admin", subject, template)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during sending notification email: {ex.Message}");
            }
        }

        private RedirectResult RedirectToLogin(AuthenticateResult result, RegistrationError regError)
        {
            var retUrl = result.Properties.Items["returnUrl"] ?? "";
            return Redirect($"/Account/Login?error={regError}&returnUrl=" + HttpUtility.UrlEncode(retUrl));
        }

        /// <summary>
        /// Handle postback from Agree to terms page
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AgreeToTerms(LoginInputModel model, string button)
        {
            // load and log in the user by the temporary token
            if (button == "agree")
            {
                var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
                if (result?.Succeeded != true)
                {
                    throw new Exception("External authentication error");
                }

                // lookup our user and external provider info
                var connector = await GetClientConnectorAsync(result).ConfigureAwait(false);
                var (user, _, _, _) = await FindUserFromExternalProvider(result, connector);
                if (user != null)
                {
                    // set agree to terms in repo
                    if (!user.AgreedToTerms)
                        await connector.SetAgreeToTermsAsync(user).ConfigureAwait(false);

                    return await Callback();
                }
            }

            return View();
        }

        /// <summary>
        /// Handle postback from create repo page
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateRepository(CreateRepositoryInputModel model, string button)
        {
            SnUser user = null;

            if (button == "create")
            {
                var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
                if (result?.Succeeded != true)
                {
                    throw new Exception("External authentication error");
                }

                // lookup our user and external provider info
                var connector = await GetClientConnectorAsync(result).ConfigureAwait(false);
                var (u, _, _, _) = await FindUserFromExternalProvider(result, connector);
                user = u;

                //TODO: handle the case when the user wants to skip repo creation

                if (user != null && !string.IsNullOrEmpty(model.Password))
                {
                    // perform additional operations after external registration
                    await _registrationManager.OnExternalRegistrationCompletedAsync(connector, user, model.Password, HttpContext.RequestAborted)
                        .ConfigureAwait(false);

                    // proceed to sign in
                    return await Callback();
                }
            }

            return View("CreateRepository", new CreateRepositoryInputModel
            {
                Email = user?.Email,
                Password = model.Password
            });
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, treating windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("Callback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.FindFirst(ClaimTypes.PrimarySid).Value));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (AccountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }

        private async Task<(SnUser user, string provider, string providerUserId, IEnumerable<Claim> claims)> 
            FindUserFromExternalProvider(AuthenticateResult result, SnClientConnector connector)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // [sensenet] find external user in the repository
            var user = await connector.GetUserByProviderAsync(provider, providerUserId).ConfigureAwait(false);

            return (user, provider, providerUserId, claims);
        }

        private Task<SnClientConnector> GetClientConnectorAsync(AuthenticateResult result)
        {
            var returnUrl = result.Ticket.Properties.GetString("returnUrl");
            return _clientConnectorFactory.CreateAsync(returnUrl);
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }
    }
}