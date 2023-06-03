using System;

namespace IdentityServer4.Quickstart.UI
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = true;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static bool ShowLogoutPrompt = true;

        //[sensenet] changed default autoredirect value
        public static bool AutomaticRedirectAfterSignOut = true;

        // specify the Windows authentication scheme being used
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // if user uses windows auth, should we load the groups from windows
        public static bool IncludeWindowsGroups = false;

        public static string InvalidCredentialsErrorMessage = "Invalid username or password";
        public static string InvalidTwoFactorErrorMessage = "Two-factor authentication failed";
        public static string InvalidRepositoryErrorMessage = "Invalid repository.";
        public static string UserClientMismatchErrorMessage = "You cannot log in using this client.";
    }
}
