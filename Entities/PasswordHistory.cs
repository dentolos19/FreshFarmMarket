namespace FreshFarmMarket.Entities;

public class PasswordHistory
{
    public int Id { get; set; }
    public required string HashedPassword { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Foreign Keys
    public required string UserId { get; set; }
    public User User { get; set; } = null!;
}
