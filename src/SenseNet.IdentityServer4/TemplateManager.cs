using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;

namespace SenseNet.IdentityServer4
{
    public interface ITemplateManager
    {
        Task<string> GetTemplateAsync(string templateName, string repositoryUrl);
    }

    public class AssemblyTemplateManager : ITemplateManager
    {
        public async Task<string> GetTemplateAsync(string templateName, string repositoryUrl)
        {
            if (!templateName.EndsWith(".html"))
                templateName += ".html";
            
            var assembly = GetAssembly();
            var templateFullName = $"{assembly.GetName().Name}.templates.{templateName}";

            await using var resourceStream = assembly.GetManifestResourceStream(templateFullName);
            if (resourceStream == null)
                throw new InvalidOperationException($"Template {templateFullName} not found.");

            using var sr = new StreamReader(resourceStream);
            return await sr.ReadToEndAsync().ConfigureAwait(false);
        }

        protected virtual Assembly GetAssembly()
        {
            return Assembly.GetExecutingAssembly();
        }
    }

    /// <summary>
    /// Helper methods that can be called on any ITemplateManager instance.
    /// </summary>
    public static class TemplateManagerExtensions
    {
        private const string EmailSubjectPattern = "\\[subject\\]:\"(?<sub>[^\"]*)\"";

        public static async Task<(string subject, string template)> LoadAndFillEmailTemplateAsync(this ITemplateManager tm, 
            string templateName, string repositoryUrl, HttpContext context, SnUser user, string returnUrl)
        {
            var template = await tm.GetTemplateAsync(templateName, repositoryUrl).ConfigureAwait(false);
            var request = context.Request;
            var confirmUrl = $"{request.Scheme}://{request.Host}/account/ConfirmRegistration?" +
                             $"returnUrl={HttpUtility.UrlEncode(returnUrl)}&token={user?.SyncGuid}";

            var subjectMatch = Regex.Match(template, EmailSubjectPattern, RegexOptions.Multiline);
            var subject = new string(subjectMatch.Groups["sub"]?.Value.Take(300).ToArray());
            if (string.IsNullOrEmpty(subject))
                subject = "Please verify your email address!";

            template = template.Replace("{Username}", user?.Username)
                .Replace("{AppName}", repositoryUrl)
                .Replace("{ConfirmUrl}", confirmUrl);

            return (subject, template);
        }
    }
}
