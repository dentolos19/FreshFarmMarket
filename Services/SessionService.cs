using Microsoft.Extensions.Caching.Memory;

namespace FreshFarmMarket.Services;

public interface ISessionService
{
    string GenerateSessionId();
    void StoreSession(string userId, string sessionId);
    bool ValidateSession(string userId, string sessionId);
    void InvalidateSession(string userId);
}

public class SessionService : ISessionService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<SessionService> _logger;

    public SessionService(IMemoryCache cache, ILogger<SessionService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public string GenerateSessionId()
    {
        return Guid.NewGuid().ToString();
    }

    public void StoreSession(string userId, string sessionId)
    {
        var cacheKey = GetCacheKey(userId);
        _cache.Set(cacheKey, sessionId, TimeSpan.FromMinutes(20));
        _logger.LogInformation("Session stored for user {UserId}", userId);
    }

    public bool ValidateSession(string userId, string sessionId)
    {
        var cacheKey = GetCacheKey(userId);

        if (_cache.TryGetValue(cacheKey, out string? storedSessionId))
        {
            return storedSessionId == sessionId;
        }

        return false;
    }

    public void InvalidateSession(string userId)
    {
        var cacheKey = GetCacheKey(userId);
        _cache.Remove(cacheKey);
        _logger.LogInformation("Session invalidated for user {UserId}", userId);
    }

    private static string GetCacheKey(string userId)
    {
        return $"Session_{userId}";
    }
}
