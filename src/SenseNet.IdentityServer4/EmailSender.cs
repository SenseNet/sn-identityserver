﻿using MailKit.Net.Smtp;
using MimeKit;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SenseNet.IdentityServer4.Configuration;

namespace SenseNet.IdentityServer4
{
    [Obsolete("Use the EmailSender feature from Tools instead.")]
    public interface IEmailSender
    {
        Task SendAsync(string email, string name, string subject, string message);
    }

    public class EmailSender : IEmailSender
    {
        private readonly EmailSettings _emailSettings;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IOptions<EmailSettings> emailSettings, ILogger<EmailSender> logger)
        {
            _emailSettings = emailSettings.Value;
            _logger = logger;
        }

        public async Task SendAsync(string email, string name, string subject, string message)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                // only log, to make the system more robust
                _logger.LogWarning($"Trying to send an email to an empty address. Subject: {subject}");
                return;
            }

            _logger?.LogTrace($"Sending email to {email}. Subject: {subject}, Server: {_emailSettings?.Server}");

            try
            {
                var mimeMessage = new MimeMessage();
                mimeMessage.From.Add(new MailboxAddress(_emailSettings.SenderName, _emailSettings.FromAddress));

                //TODO: provide an overload of this method where multiple email addresses
                // and corresponding names can be provided. Currently we use the same name
                // for all recipients.
                foreach (var emailAddress in email.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    mimeMessage.To.Add(new MailboxAddress(name, emailAddress));
                }

                mimeMessage.Subject = subject;
                mimeMessage.Body = new TextPart("html")
                {
                    Text = message
                };

                using var client = new SmtpClient
                {
                    // For demo-purposes, accept all SSL certificates (in case the server supports STARTTLS)
                    ServerCertificateValidationCallback = (s, c, h, e) => true
                };

                //UNDONE: finalize email sending security
                
                //if (_env.IsDevelopment())
                //{
                //    // The third parameter is useSSL (true if the client should make an SSL-wrapped
                //    // connection to the server; otherwise, false).
                //    await client.ConnectAsync(_emailSettings.Server, _emailSettings.Port, true);
                //}
                //else
                //{
                //    await client.ConnectAsync(_emailSettings.Server);
                //}

                //await client.ConnectAsync(_emailSettings.Server, _emailSettings.Port, true);
                await client.ConnectAsync(_emailSettings.Server, _emailSettings.Port);

                // Note: only needed if the SMTP server requires authentication
                if (!string.IsNullOrEmpty(_emailSettings.Username))
                    await client.AuthenticateAsync(_emailSettings.Username, _emailSettings.Password);

                await client.SendAsync(mimeMessage);
                await client.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                // TODO: handle exception
                _logger?.LogError(ex, "Error sending email message.");
            }
        }
    }
}
