using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.Extensions.Options;
using CaseCTRLAPI.Dto;
using System.Net;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using CaseCTRLAPI.Settings;
using Users;

namespace CaseCTRLAPI.Controllers
{
    [Route("api")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly SignInManager<Authentication> _signInManager;
        private readonly UserManager<Authentication> _userManager;
        private readonly IUserStore<Authentication> _userStore;
        private readonly IUserEmailStore<Authentication> _emailStore;
        private readonly ILogger<IdentityController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly AppSettings _appSettings;

        public IdentityController(
            UserManager<Authentication> userManager,
            IUserStore<Authentication> userStore,
            SignInManager<Authentication> signInManager,
            ILogger<IdentityController> logger,
            IEmailSender emailSender,
            IOptions<AppSettings> appSettings)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _appSettings = appSettings.Value;
        }
        
        
        private IUserEmailStore<Authentication> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<Authentication>)_userStore;
        }

        [HttpPost]
        [Route("user")]
        public async Task<IActionResult> RegisterUser([FromBody] UserDto userDto)
        {
            if (userDto == null || String.IsNullOrEmpty(userDto.UserName) || String.IsNullOrEmpty(userDto.Password))
            {
                return BadRequest(new { title = "userName or Password is empty" });
            }

            var user = Activator.CreateInstance<Authentication>();
            await _userStore.SetUserNameAsync(user, userDto.UserName, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, userDto.UserName, CancellationToken.None);
            var result = await _userManager.CreateAsync(user, userDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(new { title = String.Join(", ", result.Errors.Select(error => error.Description)) });
            }
            _logger.LogInformation($"New user {userDto.UserName} account created.");

            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var queryParams = new Dictionary<string, string>() {
                { "userId", userId },
                { "code", code },
            };
            var callbackUrl = new Uri(new Uri(_appSettings.CustomIdentity.ClientUrl ?? ""), QueryHelpers.AddQueryString("activateUser", queryParams));

            await _emailSender.SendEmailAsync(userDto.UserName, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl.ToString())}'>clicking here</a>.");
            return Ok();
        }

        [HttpPost]
        [Route("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDto confirmEmailDto)
        {
            if (confirmEmailDto == null || String.IsNullOrEmpty(confirmEmailDto.UserId) || String.IsNullOrEmpty(confirmEmailDto.Code))
            {
                return BadRequest(new { title = "UserId or Code is empty." });
            }

            var user = await _userManager.FindByIdAsync(confirmEmailDto.UserId);
            if (user == null)
            {
                return NotFound(new { title = $"Unable to load user with ID '{confirmEmailDto.UserId}'." });
            }

            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(confirmEmailDto.Code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded) return Ok();
            return BadRequest(new {
                title = "Error confirming your email. " + String.Join(", ", result.Errors.Select((error) => error.Description))
            });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] UserDto userDto)
        {
            var result = await _signInManager.PasswordSignInAsync(userDto.UserName, userDto.Password, false, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(userDto.UserName);
                if (user == null)
                {
                    return Problem(
                        title: $"Login for {userDto.UserName} is failed.",
                        statusCode: (int)HttpStatusCode.Forbidden);
                }

                return Ok(new { Token = GenerateToken(user) });
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning($"User account {userDto.UserName} locked out.");
                return Problem(
                    title: $"User account {userDto.UserName} locked out.",
                    statusCode: (int)HttpStatusCode.Forbidden
                    );
            }
            return Problem(
                title: $"Invalid username or password",
                statusCode: (int)HttpStatusCode.Forbidden
                );
        }

        protected string GenerateToken(Authentication user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.Jwt.Key ?? ""));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Sid, user.Id),
            };
            var token = new JwtSecurityToken(_appSettings.Jwt.Issuer ?? "",
                _appSettings.Jwt.Audience ?? "",
                claims,
#if DEBUG
                expires: DateTime.Now.AddDays(1),
#else
                expires: DateTime.Now.AddHours(1),
#endif
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);

        }
    }
}
