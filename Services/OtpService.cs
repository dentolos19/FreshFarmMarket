using Microsoft.Extensions.Caching.Memory;

namespace FreshFarmMarket.Services;

public interface IOtpService
{
    string GenerateOtp(string email);
    bool ValidateOtp(string email, string otp);
    void InvalidateOtp(string email);
}

public class OtpService : IOtpService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<OtpService> _logger;
    private static readonly TimeSpan OtpExpiry = TimeSpan.FromMinutes(5);

    public OtpService(IMemoryCache cache, ILogger<OtpService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public string GenerateOtp(string email)
    {
        var otp = new Random().Next(100000, 999999).ToString();
        var cacheKey = GetCacheKey(email);

        _cache.Set(cacheKey, otp, OtpExpiry);
        _logger.LogInformation("OTP generated for {Email}", email);

        return otp;
    }

    public bool ValidateOtp(string email, string otp)
    {
        var cacheKey = GetCacheKey(email);

        if (_cache.TryGetValue(cacheKey, out string? storedOtp))
        {
            if (storedOtp == otp)
            {
                _logger.LogInformation("OTP validated successfully for {Email}", email);
                return true;
            }

            _logger.LogWarning("Invalid OTP provided for {Email}", email);
        }
        else
        {
            _logger.LogWarning("OTP expired or not found for {Email}", email);
        }

        return false;
    }

    public void InvalidateOtp(string email)
    {
        var cacheKey = GetCacheKey(email);
        _cache.Remove(cacheKey);
        _logger.LogInformation("OTP invalidated for {Email}", email);
    }

    private static string GetCacheKey(string email)
    {
        return $"OTP_{email.ToLowerInvariant()}";
    }
}
