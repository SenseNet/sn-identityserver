using System.ComponentModel.DataAnnotations;
using SenseNet.IdentityServer4;

namespace IdentityServer4.Quickstart.UI
{
    public class PasswordChangeViewModel
    {
        [Required]
        public string Password { get; set; }
        [Required]
        public string Password2 { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string FullName { get; set; }

        public string ReturnUrl { get; set; }
        public string SnRepositoryUrl => IdentityTools.GetRepositoryUrl(ReturnUrl);
    }
}
