using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json.Linq;

namespace SenseNet.IdentityServer4
{
    public class SnUser
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Username { get; set; }
        public string SubjectId { get; set; }
        public string Email { get; set; }
        public string SyncGuid { get; set; }
        public string FullName { get; set; }
        public bool Enabled { get; set; }
        public bool AgreedToTerms { get; set; }

        public bool MultiFactorEnabled { get; set; }
        public bool MultiFactorRegistered { get; set; }
        public string QrCodeSetupImageUrl { get; set; }
        public string ManualEntryKey { get; set; }

        public static SnUser FromClientContent(dynamic user)
        {
            // If this is null, it means the field does not exist, therefore
            // the feature is not needed, so we set it to True.
            var agreedObject = user.AgreedToTermsOfUse;
            var agreed = agreedObject == null || ((JValue)agreedObject).Value<bool>();

            var twoFactorRegisteredObject = user.MultiFactorRegistered;
            var twoFactorRegistered = twoFactorRegisteredObject == null || ((JValue)twoFactorRegisteredObject).Value<bool>();

            return new SnUser
            {
                Id = user.Id,
                Name = user.Name,
                Username = user.LoginName,
                SubjectId = user.Id.ToString(),
                Email = user.Email,
                SyncGuid = user.SyncGuid,
                FullName = user.FullName,
                Enabled = user.Enabled,
                AgreedToTerms = agreed,
                MultiFactorRegistered = twoFactorRegistered
            };
        }
    }
}
