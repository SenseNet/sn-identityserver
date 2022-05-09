using IdentityModel;
using IdentityServer4;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SenseNet.IdentityServer4
{
    public static class IdentityExtensions
    {
        public static Task<string> GetClientJwtAsync(this IdentityServerTools isTools, string clientId)
        {
            //UNDONE: hardcoded admin user id
            return isTools.IssueClientJwtAsync(
                clientId,
                20,
                audiences: new[] { "sensenet" },
                additionalClaims: new[]
                {
                    new Claim(JwtClaimTypes.Subject, "1")
                });
        }
    }
}
