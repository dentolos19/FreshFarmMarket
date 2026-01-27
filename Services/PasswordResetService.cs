using Microsoft.Extensions.Caching.Memory;

namespace FreshFarmMarket.Services;

public interface IPasswordResetService
{
    string GenerateResetToken(string email);
    bool ValidateResetToken(string email, string token);
    void InvalidateResetToken(string email);
}

public class PasswordResetService : IPasswordResetService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<PasswordResetService> _logger;
    private static readonly TimeSpan TokenExpiry = TimeSpan.FromMinutes(30);

    public PasswordResetService(IMemoryCache cache, ILogger<PasswordResetService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public string GenerateResetToken(string email)
    {
        var token = Guid.NewGuid().ToString();
        var cacheKey = GetCacheKey(email);

        _cache.Set(cacheKey, token, TokenExpiry);
        _logger.LogInformation("Password reset token generated for {Email}", email);

        return token;
    }

    public bool ValidateResetToken(string email, string token)
    {
        var cacheKey = GetCacheKey(email);

        if (_cache.TryGetValue(cacheKey, out string? storedToken))
        {
            if (storedToken == token)
            {
                _logger.LogInformation("Password reset token validated successfully for {Email}", email);
                return true;
            }

            _logger.LogWarning("Invalid password reset token provided for {Email}", email);
        }
        else
        {
            _logger.LogWarning("Password reset token expired or not found for {Email}", email);
        }

        return false;
    }

    public void InvalidateResetToken(string email)
    {
        var cacheKey = GetCacheKey(email);
        _cache.Remove(cacheKey);
        _logger.LogInformation("Password reset token invalidated for {Email}", email);
    }

    private static string GetCacheKey(string email)
    {
        return $"password_reset_{email.ToLowerInvariant()}";
    }
}
