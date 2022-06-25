namespace IdentityServer4.Quickstart.UI
{
    public class RegistrationSurveyViewModel
    {
        // a temporary identifier for a newly registered user
        public string UserId { get; set; }
        public string Role { get; set; }
        public string ProjectType { get; set; }
        public int Experience { get; set; }
        public string AppDevelopmentMode { get; set; }
        public string[] Features { get; set; }
    }

    /// <summary>
    /// A technical class used for caching a user and the corresponding repository. It is important
    /// to not let clients modify these two related values to avoid security holes.
    /// </summary>
    internal class RepositoryUser
    {
        public int UserId { get; set; }
        public string ReturnUrl { get; set; }
    }
}
