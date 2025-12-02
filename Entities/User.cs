using Microsoft.AspNetCore.Identity;

namespace FreshFarmMarket.Entities;

public class User : IdentityUser
{
    public required string FullName { get; set; }
    public required string CreditCardNumber { get; set; }
    public required string Gender { get; set; }
    public required string MobileNumber { get; set; }
    public required string DeliveryAddress { get; set; }
    public required string PhotoUrl { get; set; }
    public required string AboutMe { get; set; }
}