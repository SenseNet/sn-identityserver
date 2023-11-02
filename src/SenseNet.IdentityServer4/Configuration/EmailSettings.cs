namespace SenseNet.IdentityServer4.Configuration
{
    // SnDocs: legacy option class, not documented
    public class EmailSettings
    {
        public string Server { get; set; }
        public int Port { get; set; }
        public string FromAddress { get; set; }
        public string SenderName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
