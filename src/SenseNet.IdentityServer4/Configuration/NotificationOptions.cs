using SenseNet.Tools.Configuration;

namespace SenseNet.IdentityServer4.Configuration
{
    /// <summary>
    /// Notification options for the sensenet authentication server.
    /// </summary>
    [OptionsClass(sectionName: "sensenet:Notification")]
    public class NotificationOptions
    {
        /// <summary>
        /// Email address of the administrator who should receive notification emails.
        /// </summary>
        public string AdminEmail { get; set; }
    }
}
