using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net.Mail;
using System.Net;
using Microsoft.Extensions.Options;
using CaseCTRLAPI.Settings;

namespace CaseCTRLAPI.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly SmtpClient _smtpClient;
        private readonly AppSettings _appSettings;
        public EmailSender(IOptions<AppSettings> appSettings,
            SmtpClient smtpClient)
        {
            _appSettings = appSettings.Value;
            _smtpClient = smtpClient;
        }
        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var mailMessage = new MailMessage
            {
                From = new MailAddress(_appSettings.EmailServer.Username ?? ""),
                Subject = subject,
                Body = message,
                IsBodyHtml = true,
            };
            mailMessage.To.Add(email);
            _smtpClient.Send(mailMessage);
        }
    }
}
