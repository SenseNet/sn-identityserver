using SenseNet.Tools.Configuration;

namespace SenseNet.IdentityServer4.Web.Captcha
{
    /// <summary>
    /// Captcha options for configuring Google reCaptcha.
    /// </summary>
    [OptionsClass(sectionName: "sensenet:Captcha")]
    public class RecaptchaOptions
    {
        /// <summary>
        /// The project id from Google Service account.
        /// </summary>
        public string ProjectId { get; set; }

        /// <summary>
        /// The private key id from Google Service account.
        /// </summary>
        public string PrivateKeyId { get; set; }

        /// <summary>
        /// The private key from Google Service account.
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        /// The client email from Google Service account.
        /// </summary>
        public string ClientEmail { get; set; }

        /// <summary>
        /// The client id from Google Service account.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// The client certificate url from Google Service account.
        /// </summary>
        public string ClientCertUrl { get; set; }

        /// <summary>
        /// The site key from Google reCaptcha.
        /// </summary>
        public string SiteKey { get; set; }

        /// <summary>
        /// The accepted score. 0.1 is worst (probably a bot), 0.9 is best (probably human).
        /// </summary>
        public float AcceptedScore { get; set; }
    }
}
