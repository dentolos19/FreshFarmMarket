using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models;

public class VerifyOtpViewModel
{
    [Required(ErrorMessage = "OTP is required")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP must be 6 digits")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "OTP must be 6 digits")]
    [Display(Name = "One-Time Password")]
    public string Otp { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;
}
