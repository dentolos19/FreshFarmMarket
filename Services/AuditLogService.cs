using FreshFarmMarket.Entities;

namespace FreshFarmMarket.Services;

public interface IAuditLogService
{
    Task LogAsync(string userId, string action);
    Task LogLoginSuccessAsync(string userId);
    Task LogLoginFailedAsync(string userId);
    Task LogLogoutAsync(string userId);
    Task LogCreditCardAccessAsync(string userId);
    Task LogPasswordChangeAsync(string userId);
}

public class AuditLogService : IAuditLogService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<AuditLogService> _logger;

    public AuditLogService(AuthDbContext context, ILogger<AuditLogService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task LogAsync(string userId, string action)
    {
        var auditLog = new AuditLog
        {
            UserId = userId,
            Action = action,
            Timestamp = DateTime.UtcNow,
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Audit: User {UserId} - {Action} at {Timestamp}", userId, action, auditLog.Timestamp);
    }

    public async Task LogLoginSuccessAsync(string userId)
    {
        await LogAsync(userId, "Login successful");
    }

    public async Task LogLoginFailedAsync(string userId)
    {
        await LogAsync(userId, "Login failed - invalid credentials");
    }

    public async Task LogLogoutAsync(string userId)
    {
        await LogAsync(userId, "User logged out");
    }

    public async Task LogCreditCardAccessAsync(string userId)
    {
        await LogAsync(userId, "Credit card data accessed/decrypted");
    }

    public async Task LogPasswordChangeAsync(string userId)
    {
        await LogAsync(userId, "Password changed");
    }
}
