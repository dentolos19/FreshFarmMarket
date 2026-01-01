namespace FreshFarmMarket.Entities;

public class AuditLog
{
    public int Id { get; set; }
    public required string Action { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Foreign Keys
    public required string UserId { get; set; }
    public User User { get; set; } = null!;
}
