using FreshFarmMarket.Entities;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FreshFarmMarket.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IDataProtectionService _dataProtectionService;
    private readonly IFileUploadService _fileUploadService;
    private readonly IRecaptchaService _recaptchaService;
    private readonly IAuditLogService _auditLogService;
    private readonly IEmailService _emailService;
    private readonly IOtpService _otpService;
    private readonly ISessionService _sessionService;
    private readonly IPasswordHistoryService _passwordHistoryService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IDataProtectionService dataProtectionService,
        IFileUploadService fileUploadService,
        IRecaptchaService recaptchaService,
        IAuditLogService auditLogService,
        IEmailService emailService,
        IOtpService otpService,
        ISessionService sessionService,
        IPasswordHistoryService passwordHistoryService,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _dataProtectionService = dataProtectionService;
        _fileUploadService = fileUploadService;
        _recaptchaService = recaptchaService;
        _auditLogService = auditLogService;
        _emailService = emailService;
        _otpService = otpService;
        _sessionService = sessionService;
        _passwordHistoryService = passwordHistoryService;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reCAPTCHA
        if (!await _recaptchaService.ValidateAsync(model.RecaptchaToken))
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        // Check if email already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            ModelState.AddModelError("Email", "An account with this email already exists.");
            return View(model);
        }

        // Upload photo
        if (model.Photo == null)
        {
            ModelState.AddModelError("Photo", "Profile photo is required.");
            return View(model);
        }

        var uploadResult = await _fileUploadService.UploadPhotoAsync(model.Photo);
        if (!uploadResult.Success)
        {
            ModelState.AddModelError("Photo", uploadResult.ErrorMessage ?? "Photo upload failed.");
            return View(model);
        }

        // Encrypt credit card number
        var encryptedCreditCard = _dataProtectionService.Encrypt(model.CreditCardNumber);

        var user = new User
        {
            UserName = model.Email,
            Email = model.Email,
            FullName = model.FullName,
            Gender = model.Gender,
            MobileNumber = model.MobileNumber,
            DeliveryAddress = model.DeliveryAddress,
            CreditCardNumber = encryptedCreditCard,
            PhotoUrl = uploadResult.FilePath!,
            AboutMe = model.AboutMe,
            LastPasswordChangedAt = DateTime.UtcNow,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            // Add password to history
            var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.Password);
            await _passwordHistoryService.AddPasswordToHistoryAsync(user.Id, hashedPassword);

            _logger.LogInformation("User {Email} registered successfully", model.Email);
            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reCAPTCHA
        if (!await _recaptchaService.ValidateAsync(model.RecaptchaToken))
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        // Check if account is locked out
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            var remainingTime = lockoutEnd?.Subtract(DateTimeOffset.UtcNow);
            ModelState.AddModelError(string.Empty,
                $"Account is locked. Please try again in {remainingTime?.Minutes ?? 10} minutes.");
            return View(model);
        }

        // Verify password
        var passwordValid = await _userManager.CheckPasswordAsync(user, model.Password);
        if (!passwordValid)
        {
            await _userManager.AccessFailedAsync(user);
            await _auditLogService.LogLoginFailedAsync(user.Id);

            if (await _userManager.IsLockedOutAsync(user))
            {
                ModelState.AddModelError(string.Empty,
                    "Account has been locked due to multiple failed login attempts. Please try again in 10 minutes.");
            }
            else
            {
                var remainingAttempts = 3 - await _userManager.GetAccessFailedCountAsync(user);
                ModelState.AddModelError(string.Empty,
                    $"Invalid login attempt. {remainingAttempts} attempts remaining before lockout.");
            }

            return View(model);
        }

        // Generate and send OTP for 2FA
        var otp = _otpService.GenerateOtp(model.Email);
        await _emailService.SendOtpAsync(model.Email, otp);

        // Store email in TempData for OTP verification
        TempData["OtpEmail"] = model.Email;
        TempData["RememberMe"] = model.RememberMe;
        TempData["ReturnUrl"] = returnUrl;

        _logger.LogInformation("OTP sent to {Email} for 2FA", model.Email);
        return RedirectToAction("VerifyOtp");
    }

    [HttpGet]
    public IActionResult VerifyOtp()
    {
        var email = TempData["OtpEmail"] as string;
        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        // Keep TempData for POST
        TempData.Keep("OtpEmail");
        TempData.Keep("RememberMe");
        TempData.Keep("ReturnUrl");

        return View(new VerifyOtpViewModel { Email = email });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyOtp(VerifyOtpViewModel model)
    {
        var email = TempData["OtpEmail"] as string;
        var rememberMe = TempData["RememberMe"] as bool? ?? false;
        var returnUrl = TempData["ReturnUrl"] as string;

        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        if (!ModelState.IsValid)
        {
            TempData["OtpEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            model.Email = email;
            return View(model);
        }

        // Validate OTP
        if (!_otpService.ValidateOtp(email, model.Otp))
        {
            ModelState.AddModelError(string.Empty, "Invalid or expired OTP. Please try again.");
            TempData["OtpEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            model.Email = email;
            return View(model);
        }

        // Invalidate OTP after successful use
        _otpService.InvalidateOtp(email);

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // Check for existing active session (concurrent login detection)
        if (!string.IsNullOrEmpty(user.CurrentSessionId))
        {
            if (_sessionService.ValidateSession(user.Id, user.CurrentSessionId))
            {
                // Invalidate previous session
                _sessionService.InvalidateSession(user.Id);
                _logger.LogWarning("Concurrent login detected for user {Email}. Previous session invalidated.", email);
            }
        }

        // Generate new session ID
        var sessionId = _sessionService.GenerateSessionId();
        user.CurrentSessionId = sessionId;
        await _userManager.UpdateAsync(user);
        _sessionService.StoreSession(user.Id, sessionId);

        // Reset access failed count
        await _userManager.ResetAccessFailedCountAsync(user);

        // Sign in the user
        await _signInManager.SignInAsync(user, rememberMe);

        // Store session ID in session for validation
        HttpContext.Session.SetString("SessionId", sessionId);

        await _auditLogService.LogLoginSuccessAsync(user.Id);
        _logger.LogInformation("User {Email} logged in successfully", email);

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user != null)
        {
            // Invalidate session
            _sessionService.InvalidateSession(user.Id);
            user.CurrentSessionId = null;
            await _userManager.UpdateAsync(user);

            await _auditLogService.LogLogoutAsync(user.Id);
        }

        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();

        _logger.LogInformation("User logged out");
        return RedirectToAction("Login");
    }

    [HttpGet]
    [Authorize]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // Check minimum password age (5 minutes)
        if (user.LastPasswordChangedAt.HasValue)
        {
            var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangedAt.Value;
            if (timeSinceLastChange.TotalMinutes < 5)
            {
                var remainingMinutes = 5 - (int)timeSinceLastChange.TotalMinutes;
                ModelState.AddModelError(string.Empty,
                    $"You can only change your password once every 5 minutes. Please wait {remainingMinutes} more minute(s).");
                return View(model);
            }
        }

        // Check password history (prevent reuse of last 2 passwords)
        if (await _passwordHistoryService.IsPasswordInHistoryAsync(user.Id, model.NewPassword, _userManager))
        {
            ModelState.AddModelError(string.Empty,
                "You cannot reuse any of your last 2 passwords. Please choose a different password.");
            return View(model);
        }

        // Change password
        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Add new password to history
        var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
        await _passwordHistoryService.AddPasswordToHistoryAsync(user.Id, hashedPassword);

        // Update last password changed timestamp
        user.LastPasswordChangedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _auditLogService.LogPasswordChangeAsync(user.Id);

        // Sign out and require re-login
        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();

        TempData["SuccessMessage"] = "Password changed successfully! Please login with your new password.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }
}
