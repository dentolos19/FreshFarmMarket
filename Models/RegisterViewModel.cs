using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Models;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Full name is required")]
    [Display(Name = "Full Name")]
    [StringLength(100, ErrorMessage = "Full name cannot exceed 100 characters")]
    public string FullName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [Display(Name = "Email Address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
    [RegularExpression(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$",
        ErrorMessage = "Password must contain at least one uppercase, one lowercase, one number, and one special character"
    )]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Gender is required")]
    [Display(Name = "Gender")]
    public string Gender { get; set; } = string.Empty;

    [Required(ErrorMessage = "Mobile number is required")]
    [Phone(ErrorMessage = "Invalid phone number format")]
    [Display(Name = "Mobile Number")]
    public string MobileNumber { get; set; } = string.Empty;

    [Required(ErrorMessage = "Delivery address is required")]
    [Display(Name = "Delivery Address")]
    [StringLength(500, ErrorMessage = "Address cannot exceed 500 characters")]
    public string DeliveryAddress { get; set; } = string.Empty;

    [Required(ErrorMessage = "Credit card number is required")]
    [CreditCard(ErrorMessage = "Invalid credit card number")]
    [Display(Name = "Credit Card Number")]
    public string CreditCardNumber { get; set; } = string.Empty;

    [Required(ErrorMessage = "Photo is required")]
    [Display(Name = "Profile Photo (.JPG only)")]
    public IFormFile? Photo { get; set; }

    [Required(ErrorMessage = "About me is required")]
    [Display(Name = "About Me")]
    [StringLength(1000, ErrorMessage = "About me cannot exceed 1000 characters")]
    public string AboutMe { get; set; } = string.Empty;

    [Required(ErrorMessage = "reCAPTCHA validation is required")]
    public string RecaptchaToken { get; set; } = string.Empty;
}
