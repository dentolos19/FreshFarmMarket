using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [Display(Name = "Email Address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "reCAPTCHA validation is required")]
    public string RecaptchaToken { get; set; } = string.Empty;
}
