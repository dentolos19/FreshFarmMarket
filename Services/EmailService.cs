using Resend;

namespace FreshFarmMarket.Services;

public interface IEmailService
{
    Task SendOtpAsync(string email, string otp);
    Task SendPasswordResetEmailAsync(string email, string resetUrl);
}

public class EmailService : IEmailService
{
    private readonly ResendClient _resendClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(ResendClient resendClient, IConfiguration configuration, ILogger<EmailService> logger)
    {
        _resendClient = resendClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendOtpAsync(string email, string otp)
    {
        var apiKey = _configuration["Resend:ApiKey"];
        var senderEmail = _configuration["Resend:SenderEmail"];
        var senderName = _configuration["Resend:SenderName"];

        // For development, just log the OTP
        if (string.IsNullOrEmpty(apiKey) || apiKey == "YOUR_RESEND_API_KEY")
        {
            _logger.LogWarning("DEVELOPMENT MODE: OTP for {Email} is {Otp}", email, otp);
            return;
        }

        try
        {
            var message = new EmailMessage
            {
                From = $"{senderName ?? "Fresh Farm Market"} <{senderEmail ?? "onboarding@resend.dev"}>",
                To = [email],
                Subject = "Your Fresh Farm Market Login OTP",
                HtmlBody =
                    $@"
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
            };

            await _resendClient.EmailSendAsync(message);
            _logger.LogInformation("OTP email sent to {Email} via Resend", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send OTP email to {Email} via Resend", email);
            throw;
        }
    }

    public async Task SendPasswordResetEmailAsync(string email, string resetUrl)
    {
        var apiKey = _configuration["Resend:ApiKey"];
        var senderEmail = _configuration["Resend:SenderEmail"];
        var senderName = _configuration["Resend:SenderName"];

        // For development, just log the reset URL
        if (string.IsNullOrEmpty(apiKey) || apiKey == "YOUR_RESEND_API_KEY")
        {
            _logger.LogWarning("DEVELOPMENT MODE: Password reset URL for {Email} is {ResetUrl}", email, resetUrl);
            return;
        }

        try
        {
            var message = new EmailMessage
            {
                From = $"{senderName ?? "Fresh Farm Market"} <{senderEmail ?? "onboarding@resend.dev"}>",
                To = [email],
                Subject = "Reset Your Fresh Farm Market Password",
                HtmlBody =
                    $@"
                    <html>
                    <body style='font-family: Arial, sans-serif; line-height: 1.6;'>
                        <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                            <h2 style='color: #4CAF50;'>🥬 Fresh Farm Market - Password Reset</h2>
                            <p>We received a request to reset your password.</p>
                            <p>Click the button below to reset your password:</p>
                            <div style='text-align: center; margin: 30px 0;'>
                                <a href='{resetUrl}' style='background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;'>Reset Password</a>
                            </div>
                            <p>Or copy and paste this link into your browser:</p>
                            <p style='background-color: #f4f4f4; padding: 10px; word-break: break-all;'>{resetUrl}</p>
                            <p style='color: #666;'>This link will expire in 30 minutes.</p>
                            <p style='color: #666;'>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
                            <br/>
                            <p>Best regards,<br/>Fresh Farm Market Team</p>
                        </div>
                    </body>
                    </html>",
            };

            await _resendClient.EmailSendAsync(message);
            _logger.LogInformation("Password reset email sent to {Email} via Resend", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email} via Resend", email);
            throw;
        }
    }
}
