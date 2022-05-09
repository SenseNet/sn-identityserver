namespace SenseNet.IdentityServer4.Configuration
{
    public class LoginPageOptions
    {
        public bool DisplayDemoSection { get; set; }
        public bool DisplayOtherRepositoryButton { get; set; }
        public bool DisplayRegistration { get; set; }
        public bool DisplayRegistrationExplanation { get; set; }
        public bool DisplayRepositoryUrl { get; set; }
        public bool DisplaySocialLoginSection { get; set; }
        public bool AddAcceptPrivacyScript { get; set; }
        public string LoginWelcomeText { get; set; }
        public string RegistrationWelcomeText { get; set; }
        public bool ForceAgreeTerms { get; set; }
        public bool AddCaptcha { get; set; }
    }
}
