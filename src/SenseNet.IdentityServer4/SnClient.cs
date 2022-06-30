using System;
using System.Collections.Generic;

namespace SenseNet.IdentityServer4
{
    public class SnClient : global::IdentityServer4.Models.Client
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string[] AllowedGroups { get; set; }
        public bool InternalClient { get; set; }
        public Repository[] RepositoryHosts { get; set; }
    }

    public class Repository
    {
        public string PublicHost { get; set; }
        public string InternalHost { get; set; }

        public override string ToString()
        {
            return !string.IsNullOrEmpty(InternalHost) ? $"{PublicHost} ({InternalHost})" : PublicHost;
        }
    }

    /// <summary>
    /// Defines client types.
    /// This is a mirror of the enum with the same name in the central SNaaS source code.
    /// </summary>
    [Flags]
    public enum ClientType
    {
        ExternalClient = 1,
        ExternalSpa = 2,
        InternalClient = 4,
        InternalSpa = 8,
        AdminUi = 16,
        All = ExternalClient | ExternalSpa | InternalClient | InternalSpa | AdminUi,
        AllExternal = ExternalClient | ExternalSpa,
        AllInternal = InternalClient | InternalSpa | AdminUi
    }

    public class SecretInfo
    {
        public string Id { get; set; }
        public string Value { get; set; }
        public DateTime CreationDate { get; set; }
        public DateTime ValidTill { get; set; }
    }

    public class ClientInfo
    {
        public string Name { get; set; }
        public string Repository { get; set; }
        public string ClientId { get; set; }
        public string UserName { get; set; }
        public string Authority { get; set; }
        public ClientType Type { get; set; }
        public List<SecretInfo> Secrets { get; set; } = new List<SecretInfo>();
    }
}
