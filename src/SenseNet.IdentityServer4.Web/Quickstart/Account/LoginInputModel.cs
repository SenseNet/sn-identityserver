using System.ComponentModel.DataAnnotations;

namespace IdentityServer4.Quickstart.UI
{
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
        public string Token { get; set; }

        public bool MultiFactorEnabled { get; set; }
        public bool MultiFactorRegistered { get; set; }
        public string QrCodeSetupImageUrl { get; set; }
        public string ManualEntryKey { get; set; }
        public string TwoFactorCode { get; set; }
    }
}