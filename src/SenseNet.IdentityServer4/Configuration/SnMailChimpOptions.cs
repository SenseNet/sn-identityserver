using System;
using MailChimp.Net;

namespace SenseNet.IdentityServer4.Configuration
{
    public class SnMailChimpOptions : MailChimpOptions
    {
        public string[] RegistrationLists { get; set; } = Array.Empty<string>();
    }
}
