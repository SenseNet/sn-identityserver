using System.Threading.Tasks;
using IdentityServer4.Validation;

namespace SenseNet.IdentityServer4
{
    public class SnAuthorizeRequestValidator : ICustomAuthorizeRequestValidator
    {
        private readonly SnClientConnectorFactory _clientConnectorFactory;

        public SnAuthorizeRequestValidator(SnClientConnectorFactory clientConnectorFactory)
        {
            _clientConnectorFactory = clientConnectorFactory;
        }

        public async Task ValidateAsync(CustomAuthorizeRequestValidationContext context)
        {
            // This method is meant to check whether the user is allowed to log in
            // using this particular client. The most important use case for this
            // is the admin ui.

            var request = context.Result.ValidatedRequest;
            if (!(request.Client is SnClient client))
                return;

            // unknown user
            var userId = request.Subject.GetUserId();
            if (userId == 0)
                return;

            // unknown repository
            var repoUrl = request.Raw["snrepo"];
            if (string.IsNullOrEmpty(repoUrl))
                return;

            // check if the repository is in the white list of accepted hosts
            if (!SnClientStore.IsAllowedRepository(repoUrl))
            {
                context.Result.IsError = true;
                context.Result.Error = "Unknown repository.";
                return;
            }

            var connector = await _clientConnectorFactory.CreateAsync(repoUrl)
                .ConfigureAwait(false);

            // if the user is not allowed to log in using this client id, deny access
            if (!await client.IsUserAllowedAsync(userId, connector).ConfigureAwait(false))
            {
                context.Result.IsError = true;
            }
        }
    }
}
