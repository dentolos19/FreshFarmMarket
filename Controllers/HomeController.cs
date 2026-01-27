using System.Diagnostics;
using System.Web;
using FreshFarmMarket.Entities;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FreshFarmMarket.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly UserManager<User> _userManager;
    private readonly IDataProtectionService _dataProtectionService;
    private readonly IAuditLogService _auditLogService;
    private readonly ISessionService _sessionService;

    public HomeController(
        ILogger<HomeController> logger,
        UserManager<User> userManager,
        IDataProtectionService dataProtectionService,
        IAuditLogService auditLogService,
        ISessionService sessionService
    )
    {
        _logger = logger;
        _userManager = userManager;
        _dataProtectionService = dataProtectionService;
        _auditLogService = auditLogService;
        _sessionService = sessionService;
    }

    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login", "Account");
        }

        // Validate session to detect concurrent logins
        var currentSessionId = HttpContext.Session.GetString("SessionId");
        if (string.IsNullOrEmpty(currentSessionId) || !_sessionService.ValidateSession(user.Id, currentSessionId))
        {
            // Session is invalid or user logged in elsewhere
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }

        // Decrypt credit card and log access
        var decryptedCreditCard = _dataProtectionService.Decrypt(user.CreditCardNumber);
        await _auditLogService.LogCreditCardAccessAsync(user.Id);

        // HTML encode AboutMe to prevent XSS
        var encodedAboutMe = HttpUtility.HtmlEncode(user.AboutMe);

        var viewModel = new UserProfileViewModel
        {
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            Gender = user.Gender,
            MobileNumber = user.MobileNumber,
            DeliveryAddress = user.DeliveryAddress,
            CreditCardNumber = decryptedCreditCard,
            PhotoUrl = user.PhotoUrl,
            AboutMe = encodedAboutMe,
        };

        return View(viewModel);
    }

    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error(int? statusCode = null)
    {
        if (statusCode.HasValue)
        {
            return statusCode.Value switch
            {
                403 => View("Error403"),
                404 => View("Error404"),
                _ => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier }),
            };
        }

        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    [AllowAnonymous]
    public IActionResult Error403()
    {
        Response.StatusCode = 403;
        return View();
    }

    [AllowAnonymous]
    public IActionResult Error404()
    {
        Response.StatusCode = 404;
        return View();
    }

    [AllowAnonymous]
    public IActionResult Error500()
    {
        Response.StatusCode = 500;
        return View();
    }
}
