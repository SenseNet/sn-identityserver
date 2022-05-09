using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.RecaptchaEnterprise.V1;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace SenseNet.IdentityServer4.Web.Captcha
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly RecaptchaOptions _recaptchaOptions;
        private readonly ILogger<RecaptchaService> _logger;

        public RecaptchaService(IOptions<RecaptchaOptions> recaptchaOptions, ILogger<RecaptchaService> logger)
        {
            _recaptchaOptions = recaptchaOptions.Value;
            _logger = logger;
        }

        #region IRecaptchaService

        public async Task<bool> VerifyAsync(string recaptchaResponse, string expectedAction, CancellationToken cancel)
        {
            if (string.IsNullOrEmpty(recaptchaResponse))
            {
                _logger.LogWarning("Captcha response is empty.");
                return false;
            }

            var credentials = new Dictionary<string, string>
            {
                { "type", "service_account" }, 
                { "project_id", _recaptchaOptions.ProjectId }, 
                { "private_key_id", _recaptchaOptions.PrivateKeyId }, 
                { "private_key", _recaptchaOptions.PrivateKey }, 
                { "client_email", _recaptchaOptions.ClientEmail }, 
                { "client_id", _recaptchaOptions.ClientId }, 
                { "auth_uri", "https://accounts.google.com/o/oauth2/auth" }, 
                { "token_uri", "https://oauth2.googleapis.com/token" }, 
                { "auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs" }, 
                { "client_x509_cert_url", _recaptchaOptions.ClientCertUrl }
            };

            var jsonCredentials = JsonConvert.SerializeObject(credentials, Formatting.Indented);
            var clientBuilder = new RecaptchaEnterpriseServiceClientBuilder
            {
                JsonCredentials = jsonCredentials
            };

            try
            {
                var client = await clientBuilder.BuildAsync(cancel).ConfigureAwait(false);

                // initialize request argument(s)
                var createAssessmentRequest = new CreateAssessmentRequest
                {
                    ParentAsProjectName = ProjectName.FromProject(_recaptchaOptions.ProjectId),
                    Assessment = new Assessment
                    {
                        Event = new Event
                        {
                            SiteKey = _recaptchaOptions.SiteKey,
                            Token = recaptchaResponse
                        }
                    },
                };

                // client from environment
                //var client = await RecaptchaEnterpriseServiceClient.CreateAsync(cancel).ConfigureAwait(false);

                var response = await client.CreateAssessmentAsync(createAssessmentRequest, cancel).ConfigureAwait(false);

                var isValid = response.TokenProperties.Valid && response.TokenProperties.Action.Equals(expectedAction) &&
                       response.RiskAnalysis?.Score >= _recaptchaOptions.AcceptedScore;

                if (!isValid)
                    _logger.LogTrace($"Invalid captcha. Score: {response.RiskAnalysis?.Score}. " +
                                     $"Expected action: {expectedAction}. Actual: {response.TokenProperties.Action}");

                return isValid;
            }
            catch (Exception e)
            {
                _logger.LogError("Error validating captcha: " + e.Message);
                return false;
            }
        }

        #endregion
    }
}
