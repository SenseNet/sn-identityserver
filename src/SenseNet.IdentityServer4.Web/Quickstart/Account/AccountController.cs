using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SenseNet.IdentityServer4;
using SenseNet.IdentityServer4.Configuration;
using SenseNet.IdentityServer4.Web.Captcha;

namespace IdentityServer4.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly ITemplateManager _templateManager;
        private readonly LoginPageOptions _loginOptions;
        private readonly NotificationOptions _notificationOptions;
        private readonly SnClientConnectorFactory _clientConnectorFactory;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IRegistrationManager _registrationManager;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            ILogger<AccountController> logger,
            IEmailSender emailSender,
            ITemplateManager templateManager,
            IOptions<LoginPageOptions> loginOptions,
            SnClientConnectorFactory clientConnectorFactory,
            IRecaptchaService recaptchaService,
            IOptions<NotificationOptions> notificationOptions,
            IRegistrationManager registrationManager)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            //_users = users ?? new TestUserStore(TestUsers.Users);

            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _logger = logger;
            _emailSender = emailSender;
            _templateManager = templateManager;
            _loginOptions = loginOptions?.Value ?? new LoginPageOptions();
            _clientConnectorFactory = clientConnectorFactory;
            _recaptchaService = recaptchaService;
            _notificationOptions = notificationOptions.Value;
            _registrationManager = registrationManager;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl, RegistrationError? error = null)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (error.HasValue)
            {
                ModelState.AddModelError(string.Empty, RegistrationException.GetMessage(error.Value));
            }

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (await _clientStore.IsPkceClientAsync(context.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                // SN: validate user
                var returnUrl = HttpContext?.Request?.Form["ReturnUrl"].FirstOrDefault();
                var connector = await _clientConnectorFactory.CreateAsync(returnUrl)
                    .ConfigureAwait(false);

                // validate username/password against the repository
                if (SnClientStore.IsAllowedRepository(connector.Server?.Url))
                {
                    var user = await connector.ValidateCredentialsAsync(model.Username, model.Password);
                    if (user != null)
                    {
                        // if the user has not agreed to terms and conditions yet, redirect to the intermediate page
                        if (_loginOptions.ForceAgreeTerms && !user.AgreedToTerms)
                        {
                            _logger.LogTrace($"User {user.Username} has not yet agreed to terms of use.");

                            // set a temporary token on the user content
                            var token = Guid.NewGuid().ToString();
                            await connector.SetTokenAsync(user, token).ConfigureAwait(false);

                            var vm1 = await BuildLoginViewModelAsync(model);
                            vm1.Token = token;
                            return View("AgreeToTerms", vm1);
                        }

                        if (await _clientStore.IsUserAllowedAsync(context?.ClientId, user.Id, connector)
                            .ConfigureAwait(false))
                        {
                            return await LogInUser(user, context, model).ConfigureAwait(false);
                        }

                        await _events.RaiseAsync(new UserLoginFailureEvent(model.Username,
                            "user is not allowed to use this client", clientId: context?.ClientId));
                        ModelState.AddModelError(string.Empty, AccountOptions.UserClientMismatchErrorMessage);
                    }
                    else
                    {
                        await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials",
                            clientId: context?.ClientId));
                        ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
                    }
                }
                else
                {
                    var repositoryList = SnClientStore.AllowedRepositories.Count > 20
                        ? "[more than 20]"
                        : string.Join(", ", SnClientStore.AllowedRepositories);
                    _logger?.LogError($"Invalid repository: {connector.Server?.Url}. Allowed repositories: " + repositoryList);

                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username,
                        "invalid repository: " + connector.Server?.Url, clientId: context?.ClientId));
                    ModelState.AddModelError(string.Empty, AccountOptions.InvalidRepositoryErrorMessage);
                }
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        private async Task<IActionResult> LogInUser(SnUser user, AuthorizationRequest context, LoginInputModel model)
        {
            // This is mostly not sensenet-related unchanged logic,
            // only it is refactored to this central method.
            _logger.LogTrace($"Logging in user {user.Username}");

            await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.ClientId));

            // only set explicit expiration here if user chooses "remember me". 
            // otherwise we rely upon expiration configured in cookie middleware.
            AuthenticationProperties props = null;
            if (AccountOptions.AllowRememberLogin && model.RememberLogin)
            {
                props = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                };
            };

            // issue authentication cookie with subject ID and username
            await HttpContext.SignInAsync(user.SubjectId, user.Username, props);

            if (context != null)
            {
                if (await _clientStore.IsPkceClientAsync(context.ClientId))
                {
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                }

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                return Redirect(model.ReturnUrl);
            }

            // request for a local page
            if (Url.IsLocalUrl(model.ReturnUrl))
                return Redirect(model.ReturnUrl);
            
            if (string.IsNullOrEmpty(model.ReturnUrl))
                return Redirect("~/");
            
            // user might have clicked on a malicious link - should be logged
            throw new Exception("invalid return URL");
        }

        /// <summary>
        /// Handle postback from Agree to terms page
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AgreeToTerms(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // load and log in the user by the temporary token
            if (button == "agree" && !string.IsNullOrEmpty(model.Token))
            {
                var returnUrl = HttpContext?.Request?.Form["ReturnUrl"].FirstOrDefault();
                var connector = await _clientConnectorFactory.CreateAsync(returnUrl)
                    .ConfigureAwait(false);

                _logger.LogTrace($"Agree to terms action parameters are valid. Username: {model.Username}, " +
                                 $"token: {model.Token}, return url: {returnUrl}, server: {connector.Server?.Url}");

                var user = await connector.GetUserByTokenAsync(model.Token).ConfigureAwait(false);
                if (user != null)
                {
                    // set agree to terms in repo
                    if (!user.AgreedToTerms)
                        await connector.SetAgreeToTermsAsync(user).ConfigureAwait(false);

                    return await LogInUser(user, context, model);
                }
                else
                {
                    _logger.LogTrace($"User not found by token {model.Token} in repository {connector.Server.Url}");
                }
            }

            // something went wrong
            _logger?.LogWarning("Could not process Agree to terms request. " +
                                $"Button: {button}, User: {model.Username}, token: {model.Token}.");

            return View();
        }


        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Registration(string returnUrl)
        {
            // build a model so we know what to show on the registration page
            var vm = await BuildRegistrationViewModelAsync(returnUrl);
            return View(vm);
        }
        [HttpPost]
        public async Task<IActionResult> Registration(RegistrationViewModel model, string button)
        {
            const string defaultErrorMessage = "There was an error during registration. The service may be inaccessible.";

            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button != "register")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (await _clientStore.IsPkceClientAsync(context.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }

                    return Redirect(model.ReturnUrl);
                }

                // since we don't have a valid context, then we just go back to the home page
                return Redirect("~/");
            }

            if (_loginOptions.AddCaptcha)
            {
                var isValid = await _recaptchaService.VerifyAsync(model.CaptchaToken, "register", CancellationToken.None)
                    .ConfigureAwait(false);

                if (!isValid)
                {
                    _logger.LogTrace("reCaptcha validation failed.");

                    ModelState.AddModelError(string.Empty, "Captcha validation failed.");

                    return View(model);
                }
            }

            if (ModelState.IsValid)
            {
                var connector = await _clientConnectorFactory.CreateAsync(model.ReturnUrl)
                    .ConfigureAwait(false);

                SnUser user;

                try
                {
                    // create user (it should not be enabled)
                    user = await connector.CreateLocalUserAsync(model.Username, model.Password, model.Username);
                }
                catch (RegistrationException rex)
                {
                    _logger?.LogError(rex, $"Error during user registration to {model.SnRepositoryUrl}. Username: {model.Username}. {rex.Error}");

                    ModelState.AddModelError(string.Empty, rex.Message);

                    await SendRegistrationNotification(model, rex);

                    return View(model);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, $"Error during user registration to {model.SnRepositoryUrl}. Username: {model.Username}");

                    // do not pass on the real error message to the GUI
                    ModelState.AddModelError(string.Empty, defaultErrorMessage);

                    await SendRegistrationNotification(model, ex);

                    return View(model);
                }

                try
                {
                    var (subject, template) = await _templateManager.LoadAndFillEmailTemplateAsync("email.confirm-registration",
                        model.SnRepositoryUrl, HttpContext, user, model.ReturnUrl).ConfigureAwait(false);

                    await _emailSender.SendAsync(user.Email, user.Username, subject, template).ConfigureAwait(false);

                    await SendRegistrationNotification(model);

                    if (_loginOptions.RegistrationSurvey)
                    {
                        var userToken = Guid.NewGuid().ToString();

                        UserCache.Set(userToken, new RepositoryUser
                        {
                            UserId = user.Id,
                            ReturnUrl = model.ReturnUrl
                        }, new MemoryCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
                            Size = 1
                        });

                        // redirect to a survey page
                        return View("RegistrationSurvey", new RegistrationSurveyViewModel
                        {
                            UserId = userToken
                        });
                    }

                    // redirect to a dedicated thanks page, without sign in
                    return View("ConfirmEmailSent", model);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, $"Error sending email after user registration to {model.SnRepositoryUrl}. Username: {model.Username}");

                    // do not pass on the real error message to the GUI
                    ModelState.AddModelError(string.Empty, "Registration was successful but the confirmation email could not " +
                                                           "be sent. Please contact the administrator for how to proceed.");

                    await SendRegistrationNotification(model, ex);
                }
            }
            
            return View(model);
        }

        private static readonly MemoryCache UserCache = new MemoryCache(new MemoryDistributedCacheOptions());

        // This is a test action. This page should be displayed only
        // at the end of registration.
        //[HttpGet]
        //public IActionResult RegistrationSurvey()
        //{
        //    var userToken = Guid.NewGuid().ToString();

        //    UserCache.Set(userToken, new RepositoryUser
        //    {
        //        UserId = 123,
        //        ReturnUrl = "https://localhost:44362"
        //    }, new MemoryCacheEntryOptions
        //    {
        //        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
        //        Size = 1
        //    });

        //    return View(new RegistrationSurveyViewModel
        //    {
        //        UserId = userToken
        //    });
        //}

        [HttpPost]
        public async Task<IActionResult> RegistrationSurvey(RegistrationSurveyViewModel model, string button)
        {
            // The prerequisite of the registration survey feature is that
            // this container should exist in the repository, so that
            // survey results can be saved.
            // Also a content type named 'RegistrationSurveyItem' should
            // exist too (see expected fields below).
            const string surveyListPath = "/Root/Content/RegistrationSurvey";

            // load the user data from cache
            if (!UserCache.TryGetValue(model.UserId, out RepositoryUser user))
                return View("ConfirmEmailSent", new RegistrationViewModel());

            var connector = await _clientConnectorFactory.CreateAsync(user.ReturnUrl)
                .ConfigureAwait(false);
            
            try
            {
                // check if the container exists before saving the result
                if (!await SenseNet.Client.Content.ExistsAsync(surveyListPath, connector.Server).ConfigureAwait(false))
                {
                    _logger.LogWarning($"Survey result could not be saved. Parent {surveyListPath} is missing from {connector.Server.Url}");
                    return View("ConfirmEmailSent", new RegistrationViewModel());
                }

                dynamic userContent = await SenseNet.Client.Content.LoadAsync(user.UserId, connector.Server)
                        .ConfigureAwait(false);

                // save a survey item in the repository for later use
                await connector.CreateContentAsync(surveyListPath, "RegistrationSurveyItem", "RegistrationSurveyItem",
                    new Dictionary<string, object>
                    {
                    { "RegisteredUserEmail", (string)userContent.Email },
                    { "RegisteredUser", (int)userContent.Id },
                    { "SurveyResultRole", model.Role },
                    { "SurveyResultProjectType", model.ProjectType },
                    { "SurveyResultExperience", model.Experience },
                    { "SurveyResultAppDevelopmentMode", model.AppDevelopmentMode },
                    { "SurveyResultFeatures", string.Join(',', model.Features) }
                    }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during survey result saving: {ex.Message}. User: {user.UserId}, repository: {connector.Server.Url}");
            }

            return View("ConfirmEmailSent", new RegistrationViewModel());
        }

        private async Task SendRegistrationNotification(RegistrationViewModel model, Exception exception)
        {
            await SendRegistrationNotification("email.internal-registration-error", (subject, template) =>
            {
                template = template.Replace("{Username}", model.Username)
                    .Replace("{Email}", model.Username)
                    .Replace("{UserType}", "local user")
                    .Replace("{ErrorMessage}", exception.Message)
                    .Replace("{Repository}", model.SnRepositoryUrl);

                return (subject, template);
            });
        }
        private async Task SendRegistrationNotification(RegistrationViewModel model)
        {
            await SendRegistrationNotification("email.internal-registration-success", (subject, template) =>
            {
                template = template.Replace("{Username}", model.Username)
                    .Replace("{Email}", model.Username)
                    .Replace("{UserType}", "local user")
                    .Replace("{Repository}", model.SnRepositoryUrl);

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

        [HttpGet]
        public async Task<IActionResult> ConfirmRegistration(string token, string returnUrl)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException(nameof(token));

            var connector = await _clientConnectorFactory.CreateAsync(returnUrl)
                .ConfigureAwait(false);

            _logger.LogTrace($"Confirming registration for token {token}. Repository: {connector.Server?.Url}");

            var user = await connector.GetUserByTokenAsync(token).ConfigureAwait(false);
            if (user == null)
            {
                _logger.LogWarning($"User NOT FOUND by token {token}. Repository: {connector.Server?.Url}");
                return View("ConfirmError");
            }
            else
            {
                _logger.LogTrace($"User {user.Email} loaded. Repository: {connector.Server?.Url}");
            }

            // perform additional operations after registration (in snaas: assign a new repository)
            await _registrationManager.OnRegistrationConfirmedAsync(connector, user, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            if (_loginOptions.ForceAgreeTerms && !user.AgreedToTerms)
            {
                _logger.LogTrace($"User {user.Email} has not agreed to terms yet, showing Agree to terms view.");

                return View("AgreeToTerms", new LoginViewModel
                {
                    ReturnUrl = returnUrl,
                    Token = token,
                    Username = user.Username
                });
            }

            _logger.LogTrace($"Enabling user {user.Email} in repository {connector.Server?.Url}");

            user = await connector.EnableUserByTokenAsync(token).ConfigureAwait(false);
            if (user != null)
            {
                _logger.LogTrace($"Signing in user {user.Username} and redirecting to {returnUrl}");

                // issue authentication cookie for user
                await HttpContext.SignInAsync(user.SubjectId, user.Username);

                return Redirect(returnUrl);
            }

            _logger.LogWarning($"User not found and could not be enabled. Token: {token}. Repository: {connector.Server.Url}");

            return View("ConfirmError");
        }

        [HttpGet]
        public async Task<IActionResult> PasswordChange(string token, string returnUrl)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException(nameof(token));

            var connector = await _clientConnectorFactory.CreateAsync(returnUrl)
                .ConfigureAwait(false);

            var user = await connector.GetUserByTokenAsync(token).ConfigureAwait(false);

            if (user != null)
            {
                return View(new PasswordChangeViewModel
                {
                    ReturnUrl = returnUrl,
                    FullName = user.FullName ?? user.Username
                });
            }

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> PasswordChange(PasswordChangeViewModel vm, string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException(nameof(token));

            var connector = await _clientConnectorFactory.CreateAsync(vm.ReturnUrl)
                .ConfigureAwait(false);
            var user = await connector.SetPasswordByTokenAsync(token, vm.Password).ConfigureAwait(false);

            if (user != null)
            {
                // issue authentication cookie for user
                await HttpContext.SignInAsync(user.SubjectId, user.Username);

                return Redirect(vm.ReturnUrl);
            }

            return View();
        }
        
        [HttpGet]
        public IActionResult ForgottenPassword(string username, string returnUrl)
        {
            return View(new ForgottenPasswordInputModel
            {
                Username = username,
                ReturnUrl = returnUrl
            });
        }

        [HttpPost]
        public async Task<IActionResult> ForgottenPassword(ForgottenPasswordInputModel model)
        {
            if (!string.IsNullOrEmpty(model?.Username))
            {
                //TODO: check email correctly
                if (!model.Username.Contains("@"))
                {
                    ModelState.AddModelError(string.Empty, "Please provide an email address.");
                    return View(model);
                }

                var connector = await _clientConnectorFactory.CreateAsync(model.ReturnUrl)
                    .ConfigureAwait(false);

                await connector.SendChangePasswordMailAsync(model.Username, model.ReturnUrl).ConfigureAwait(false);

                return View("ConfirmForgottenPassword", model);
            }

            return View(model);
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<RegistrationViewModel> BuildRegistrationViewModelAsync(string returnUrl)
        {
            // This method is a fork of the BuildLoginViewModelAsync method above.
            // In case that changes, port changes here.

            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new RegistrationViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new RegistrationViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
