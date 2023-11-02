using System;
using MailChimp.Net;

namespace SenseNet.IdentityServer4.Configuration
{
    // SnDocs: legacy option class, not documented
    public class SnMailChimpOptions : MailChimpOptions
    {
        public string[] RegistrationLists { get; set; } = Array.Empty<string>();
    }
}
