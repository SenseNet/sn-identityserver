using System;
using System.Linq;
using System.Threading.Tasks;
using MailChimp.Net;
using MailChimp.Net.Interfaces;
using MailChimp.Net.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SenseNet.IdentityServer4.Configuration;

namespace SenseNet.IdentityServer4
{
    public interface IMailingListManager
    {
        Task Subscribe(SnUser user);
    }

    public class MailingListManager : IMailingListManager
    {
        private readonly ILogger _logger;
        private readonly IMailChimpManager _mailChimpManager;
        private readonly SnMailChimpOptions _options;

        public MailingListManager(IOptions<SnMailChimpOptions> options, ILogger<MailingListManager> logger)
        {
            _logger = logger;
            _options = options.Value;

            // check if there is a valid configuration
            if (string.IsNullOrEmpty(_options.ApiKey)) 
                return;

            // workaround for the DataCenter property setter early initialization
            if (string.IsNullOrEmpty(_options.DataCenter))
                _options.DataCenter = null;

            _mailChimpManager = new MailChimpManager(_options);
        }

        public async Task Subscribe(SnUser user)
        {
            if (_mailChimpManager == null || string.IsNullOrEmpty(user?.Email))
                return;

            try
            {
                var lists = await _mailChimpManager.Lists.GetAllAsync().ConfigureAwait(false);
                var list = _options.RegistrationLists.Any()
                    ? lists.FirstOrDefault(ml => _options.RegistrationLists.Contains(ml.Name))
                    : lists.FirstOrDefault();

                if (list == null)
                {
                    _logger.LogWarning("MailChimp list not found. " +
                                       $"Configured list names: {string.Join(", ", _options.RegistrationLists)}");
                    return;
                }

                var member = new Member
                {
                    EmailAddress = user.Email, 
                    StatusIfNew = Status.Subscribed
                };

                member.MergeFields.Add("FNAME", user.FullName ?? user.Name ?? user.Email);
                //member.MergeFields.Add("LNAME", "");

                await _mailChimpManager.Members.AddOrUpdateAsync(list.Id, member);

                _logger.LogTrace($"User {user.Username} has been added to mailing list {list.Name}.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during subscribing {user.Username} to the mailing list. {ex.Message}");
            }
        }
    }
}