using System.Net;
using System.Net.Mail;

namespace FreshFarmMarket.Services;

public interface IEmailService
{
    Task SendOtpAsync(string email, string otp);
}

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendOtpAsync(string email, string otp)
    {
        var smtpServer = _configuration["Email:SmtpServer"];
        var smtpPort = int.Parse(_configuration["Email:SmtpPort"] ?? "587");
        var senderEmail = _configuration["Email:SenderEmail"];
        var senderName = _configuration["Email:SenderName"];
        var username = _configuration["Email:Username"];
        var password = _configuration["Email:Password"];

        // For development, just log the OTP
        if (string.IsNullOrEmpty(smtpServer) || smtpServer == "smtp.example.com")
        {
            _logger.LogWarning("DEVELOPMENT MODE: OTP for {Email} is {Otp}", email, otp);
            return;
        }

        try
        {
            using var client = new SmtpClient(smtpServer, smtpPort);
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var mailMessage = new MailMessage
            {
                From = new MailAddress(senderEmail ?? "noreply@freshfarmmarket.com", senderName ?? "Fresh Farm Market"),
                Subject = "Your Fresh Farm Market Login OTP",
                Body = $@"
                    <html>
                    <body>
                        <h2>Fresh Farm Market - Login Verification</h2>
                        <p>Your one-time password (OTP) is:</p>
                        <h1 style='color: #4CAF50; font-size: 32px; letter-spacing: 5px;'>{otp}</h1>
                        <p>This OTP is valid for 5 minutes.</p>
                        <p>If you did not request this, please ignore this email.</p>
                        <br/>
                        <p>Best regards,<br/>Fresh Farm Market Team</p>
                    </body>
                    </html>",
                IsBodyHtml = true
            };
            mailMessage.To.Add(email);

            await client.SendMailAsync(mailMessage);
            _logger.LogInformation("OTP email sent to {Email}", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send OTP email to {Email}", email);
            throw;
        }
    }
}
