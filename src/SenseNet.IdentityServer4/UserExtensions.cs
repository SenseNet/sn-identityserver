using System;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Extensions;
using IdentityServer4.Stores;

namespace SenseNet.IdentityServer4
{
    public static class UserExtensions
    {
        public static async Task<bool> IsUserAllowedAsync(this IClientStore clientStore, string clientId, int userId,
            SnClientConnector connector)
        {
            if (string.IsNullOrEmpty(clientId))
                return false;

            var client = await clientStore.FindEnabledClientByIdAsync(clientId).ConfigureAwait(false);
            if (!(client is SnClient snClient))
                return false;

            return await snClient.IsUserAllowedAsync(userId, connector).ConfigureAwait(false);
        }
        internal static async Task<bool> IsUserAllowedAsync(this SnClient client, int userId,
            SnClientConnector connector)
        {
            if (client == null)
                return false;

            if (client.AllowedGroups == null || client.AllowedGroups.Length == 0)
                return true;

            return await connector.IsInGroup(userId, client.AllowedGroups).ConfigureAwait(false);
        }

        internal static int GetUserId(this ClaimsPrincipal principal)
        {
            try
            {
                if (!principal.HasClaim(cl => cl.Type == "sub"))
                    return 0;

                var sub = principal.Identity.GetSubjectId();
                if (sub == null || !int.TryParse(sub, out var userId))
                    return 0;

                return userId;
            }
            catch (Exception)
            {
                return 0;
            }
        }
    }
}
