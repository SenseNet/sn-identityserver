using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Linq;

namespace SenseNet.IdentityServer4
{
    public static class IdentityTools
    {
        /// <summary>
        /// Extracts the repository url from the return url. First it looks for
        /// the 'snrepo' parameter. If it is not present, the fallback is the
        /// domain in the 'redirect_uri' parameter.
        /// </summary>
        public static string GetRepositoryUrl(string returnUrl)
        {
            var snRepoUrl = string.Empty;

            if (!string.IsNullOrEmpty(returnUrl))
            {
                // parse return url just to extract the repo url
                if (returnUrl.StartsWith("/"))
                    returnUrl = "http://example.com" + returnUrl;

                try
                {
                    var parsedReturnUri = new Uri(returnUrl);
                    var query = QueryHelpers.ParseQuery(parsedReturnUri.Query);

                    // in normal cases this parameter is available
                    if (query.ContainsKey("snrepo"))
                        snRepoUrl = query["snrepo"].FirstOrDefault();

                    if (string.IsNullOrEmpty(snRepoUrl) && query.TryGetValue("redirect_uri", out var redirectUri))
                    {
                        var parsedRedirectUri = new Uri(redirectUri);
                        snRepoUrl = parsedRedirectUri.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped);
                    }
                }
                catch
                {
                    // unknown return url format
                }
            }

            return snRepoUrl;
        }

        public static string TrimSchema(this string url)
        {
            if (url == null)
                return null;

            var schIndex = url.IndexOf("://", StringComparison.OrdinalIgnoreCase);

            return (schIndex >= 0 ? url[(schIndex + 3)..] : url).Trim('/', ' ');
        }
        public static string AppendSchema(this string url)
        {
            if (string.IsNullOrEmpty(url) || url.StartsWith("http"))
                return url;

            return "https://" + url;
        }
    }
}
