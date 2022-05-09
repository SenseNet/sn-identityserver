using System.ComponentModel.DataAnnotations;
using SenseNet.IdentityServer4;

namespace IdentityServer4.Quickstart.UI
{
    public class CreateRepositoryInputModel
    {
        [Required]
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public string Email { get; set; }

        public string SnRepositoryUrl => IdentityTools.GetRepositoryUrl(ReturnUrl);
    }
}
