using System.Threading.Tasks;
using IdentityServer4.Validation;
using Microsoft.Extensions.Configuration;

namespace SenseNet.IdentityServer4
{
    public class SnAuthorizeRequestValidator : ICustomAuthorizeRequestValidator
    {
        private readonly SnClientConnectorFactory _clientConnectorFactory;
        private readonly IConfiguration _configuration;

        public SnAuthorizeRequestValidator(SnClientConnectorFactory clientConnectorFactory, IConfiguration configuration)
        {
            _clientConnectorFactory = clientConnectorFactory;
            _configuration = configuration;
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

            var serverUrl = _configuration["sensenet:authentication:containerHost"];
            if (string.IsNullOrWhiteSpace(serverUrl))
                serverUrl = repoUrl;
            var connector = await _clientConnectorFactory.CreateAsync(serverUrl)
                .ConfigureAwait(false);

            // if the user is not allowed to log in using this client id, deny access
            if (!await client.IsUserAllowedAsync(userId, connector).ConfigureAwait(false))
            {
                context.Result.IsError = true;
            }
        }
    }
}
