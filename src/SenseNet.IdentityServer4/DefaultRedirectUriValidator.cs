using System.Threading.Tasks;
using IdentityServer4.Validation;

namespace SenseNet.IdentityServer4
{
    public class DefaultRedirectUriValidator : IRedirectUriValidator
    {
        public Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, global::IdentityServer4.Models.Client client)
        {
            //UNDONE: validate redirect url using a whitelist
            return Task.FromResult(true);
        }

        public Task<bool> IsRedirectUriValidAsync(string requestedUri, global::IdentityServer4.Models.Client client)
        {
            //UNDONE: validate redirect url using a whitelist
            return Task.FromResult(true);
        }
    }
}
