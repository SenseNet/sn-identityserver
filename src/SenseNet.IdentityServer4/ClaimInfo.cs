using System.Security.Claims;

namespace SenseNet.IdentityServer4
{
    class ClaimInfo
    {
        private readonly Claim _claim;
        public ClaimInfo(Claim claim)
        {
            _claim = claim;
        }

        public string Type => _claim.Type;
        public string Value => _claim.Value;
    }
}
