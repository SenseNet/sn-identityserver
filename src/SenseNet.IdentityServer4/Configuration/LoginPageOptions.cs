namespace SenseNet.IdentityServer4.Configuration
{
    /// <summary>
    /// Options for login and registration screen on the sensenet authentication server.
    /// </summary>
    public class LoginPageOptions
    {
        /// <summary>
        /// Display the demo section.
        /// </summary>
        public bool DisplayDemoSection { get; set; }
        /// <summary>
        /// Display the Log in to another repository button.
        /// </summary>
        public bool DisplayOtherRepositoryButton { get; set; }
        /// <summary>
        /// Display registration button.
        /// </summary>
        public bool DisplayRegistration { get; set; }
        /// <summary>
        /// Display the registration details panel.
        /// </summary>
        public bool DisplayRegistrationExplanation { get; set; }
        /// <summary>
        /// Display client application url on the login screen.
        /// </summary>
        public bool DisplayClientApplication { get; set; }
        /// <summary>
        /// Display the repository url on the login screen.
        /// </summary>
        public bool DisplayRepositoryUrl { get; set; }
        /// <summary>
        /// Display social login buttons (e.g. Github, Google).
        /// </summary>
        public bool DisplaySocialLoginSection { get; set; }
        /// <summary>
        /// Add Accept privacy policy script to the page.
        /// </summary>
        public bool AddAcceptPrivacyScript { get; set; }
        public string LoginWelcomeText { get; set; }
        /// <summary>
        /// A custom registration welcome text.
        /// </summary>
        public string RegistrationWelcomeText { get; set; }
        /// <summary>
        /// Do not let the user log in until they accepted the terms of usage.
        /// </summary>
        public bool ForceAgreeTerms { get; set; }
        /// <summary>
        /// Display a captcha on the login page.
        /// </summary>
        public bool AddCaptcha { get; set; }
        /// <summary>
        /// Ask the user to fill a survey after registration.
        /// </summary>
        public bool RegistrationSurvey { get; set; }
    }
}
