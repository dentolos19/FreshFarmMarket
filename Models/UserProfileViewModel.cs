namespace FreshFarmMarket.Models;

public class UserProfileViewModel
{
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Gender { get; set; } = string.Empty;
    public string MobileNumber { get; set; } = string.Empty;
    public string DeliveryAddress { get; set; } = string.Empty;
    public string CreditCardNumber { get; set; } = string.Empty;
    public string PhotoUrl { get; set; } = string.Empty;
    public string AboutMe { get; set; } = string.Empty;
    public DateTime? LastPasswordChangedAt { get; set; }
    public int MinPasswordAgeMinutes { get; set; }
    public int MaxPasswordAgeDays { get; set; }
    public int DaysUntilPasswordExpires { get; set; }
    public int MinutesUntilCanChangePassword { get; set; }
}
