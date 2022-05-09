using System.ComponentModel.DataAnnotations;
using SenseNet.IdentityServer4;

namespace IdentityServer4.Quickstart.UI
{
    public class ForgottenPasswordInputModel
    {
        [Required]
        public string Username { get; set; }
        public string ReturnUrl { get; set; }
        public string SnRepositoryUrl => IdentityTools.GetRepositoryUrl(ReturnUrl);
    }
}
