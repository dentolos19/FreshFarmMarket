using FreshFarmMarket.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Services;

public interface IPasswordHistoryService
{
    Task AddPasswordToHistoryAsync(string userId, string hashedPassword);
    Task<bool> IsPasswordInHistoryAsync(string userId, string newPassword, UserManager<User> userManager);
}

public class PasswordHistoryService : IPasswordHistoryService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<PasswordHistoryService> _logger;
    private const int PasswordHistoryCount = 2;

    public PasswordHistoryService(AuthDbContext context, ILogger<PasswordHistoryService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task AddPasswordToHistoryAsync(string userId, string hashedPassword)
    {
        var passwordHistory = new PasswordHistory
        {
            UserId = userId,
            HashedPassword = hashedPassword,
            CreatedAt = DateTime.UtcNow
        };

        _context.PasswordHistories.Add(passwordHistory);
        await _context.SaveChangesAsync();

        // Keep only the last N passwords
        var oldPasswords = await _context.PasswordHistories
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CreatedAt)
            .Skip(PasswordHistoryCount)
            .ToListAsync();

        if (oldPasswords.Count != 0)
        {
            _context.PasswordHistories.RemoveRange(oldPasswords);
            await _context.SaveChangesAsync();
        }

        _logger.LogInformation("Password added to history for user {UserId}", userId);
    }

    public async Task<bool> IsPasswordInHistoryAsync(string userId, string newPassword, UserManager<User> userManager)
    {
        var passwordHistories = await _context.PasswordHistories
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CreatedAt)
            .Take(PasswordHistoryCount)
            .ToListAsync();

        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        foreach (var history in passwordHistories)
        {
            // Use the password hasher to verify
            var result = userManager.PasswordHasher.VerifyHashedPassword(user, history.HashedPassword, newPassword);
            if (result == PasswordVerificationResult.Success || result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                _logger.LogWarning("User {UserId} attempted to reuse a previous password", userId);
                return true;
            }
        }

        return false;
    }
}
