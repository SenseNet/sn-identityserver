using SenseNet.Tools.Configuration;

namespace SenseNet.IdentityServer4.Web.Captcha
{
    /// <summary>
    /// Captcha options for configuring Google reCaptcha.
    /// </summary>
    [OptionsClass(sectionName: "sensenet:Captcha")]
    public class RecaptchaOptions
    {
        //public string Type { get; set; } // from Google Service account

        public string ProjectId { get; set; } // from Google Service account

        public string PrivateKeyId { get; set; } // from Google Service account

        public string PrivateKey { get; set; } // from Google Service account

        public string ClientEmail { get; set; } // from Google Service account

        public string ClientId { get; set; } // from Google Service account

        public string ClientCertUrl { get; set; } // from Google Service account

        public string SiteKey { get; set; } // from Google reCaptcha

        /// <summary>
        /// 0.1 is worst (probably a bot), 0.9 is best (probably human)
        /// </summary>
        public float AcceptedScore { get; set; }
    }
}
