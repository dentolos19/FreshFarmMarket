namespace FreshFarmMarket.Entities;

public class Log
{
    public int Id { get; set; }
    public required string Activity { get; set; }
    public required string Address { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Foreign Keys
    public required string UserId { get; set; }
    public User User { get; set; } = null!;
}