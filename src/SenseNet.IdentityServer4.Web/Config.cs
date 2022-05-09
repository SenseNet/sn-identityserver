using IdentityServer4.Models;
using System.Collections.Generic;

namespace SenseNet.IdentityServer4.Web
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiResource> GetApis()
        {
            return new List<ApiResource>
            {
                new ApiResource("sensenet", "My API")
            };
        }
    }
}