using System;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SocialLogin.Models;

namespace SocialLogin.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }
            string socialNet = loginInfo.Login.LoginProvider;

            var identity = AuthenticationManager.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie);
            var emailClaim = identity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            var lastNameClaim = identity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname);
            var givenNameClaim = identity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName);
            var idClaim = identity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            var email = emailClaim != null ? emailClaim.Value : "";
            var firstName = givenNameClaim != null ? givenNameClaim.Value : "";
            var lastname = lastNameClaim != null ? lastNameClaim.Value : "";
            string picture;
            var authenUser = new AuthenticatedUser()
            {
                id = idClaim.Value,
                Email = email,
                FirstName = firstName,
                LastName = lastname,
                UserName = emailClaim != null ? email.Split('@')[0].ToString() : "",
                //Photo = picture
            };
            switch (socialNet)
            {
                case "Google":
                    {
                        var accessToken = loginInfo.ExternalIdentity.Claims.Where(c => c.Type.Equals("urn:google:accesstoken")).Select(c => c.Value).FirstOrDefault();
                        Uri apiRequestUri = new Uri("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken);
                        dynamic userPicture;
                        //request profile image
                        using (var webClient = new System.Net.WebClient())
                        {
                            var json = webClient.DownloadString(apiRequestUri);
                            dynamic resul = JsonConvert.DeserializeObject(json);
                            userPicture = resul.picture;
                        }
                        picture = userPicture;
                        authenUser.Photo = picture;
                    }
                    break;
                case "Twitter":
                    {
                        var userId = loginInfo.ExternalIdentity.Claims.Where(c => c.Type.Equals("urn:twitter:userid")).Select(c => c.Value).FirstOrDefault();
                        var screen_username = loginInfo.ExternalIdentity.Claims.Where(c => c.Type.Equals("urn:twitter:screenname")).Select(c => c.Value).FirstOrDefault();
                        var oAuthUrl = "https://api.twitter.com/oauth2/token";
                        // Do the Authenticate and get token
                        var authHeaderFormat = "Basic {0}";
                        var authHeader = string.Format(authHeaderFormat,
                            Convert.ToBase64String(Encoding.UTF8.GetBytes(Uri.EscapeDataString("yZjAVRONCLXgzXFHOuJR0BaA8") + ":" +
                            Uri.EscapeDataString(("yffpZNdRKzkdKm6WjskcROWbmN53vVCCjY34QSavdhQG346SI0")))
                        ));
                        var postBody = "grant_type=client_credentials";
                        HttpWebRequest authRequest = (HttpWebRequest)WebRequest.Create(oAuthUrl);
                        authRequest.Headers.Add("Authorization", authHeader);
                        authRequest.Method = "POST";
                        authRequest.ContentType = "application/x-www-form-urlencoded;charset=UTF-8";
                        authRequest.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                        using (Stream stream = authRequest.GetRequestStream())
                        {
                            byte[] content = ASCIIEncoding.ASCII.GetBytes(postBody);
                            stream.Write(content, 0, content.Length);
                        }

                        authRequest.Headers.Add("Accept-Encoding", "gzip");

                        WebResponse authResponse = authRequest.GetResponse();
                        // deserialize into an object
                        TwitAuthenticateResponse twitAuthResponse;
                        using (authResponse)
                        {
                            using (var reader = new StreamReader(authResponse.GetResponseStream()))
                            {
                                var objectText = reader.ReadToEnd();
                                twitAuthResponse = JsonConvert.DeserializeObject<TwitAuthenticateResponse>(objectText);
                            }
                        }
                        Uri apiRequestUri = new Uri("https://api.twitter.com/1.1/users/show.json?screen_name=" + screen_username);
                        dynamic userPicture;
                        string _name;
                        //request profile image
                        using (var webClient = new System.Net.WebClient())
                        {
                            var timelineHeaderFormat = "{0} {1}";
                            webClient.Headers.Add("Authorization", string.Format(timelineHeaderFormat, twitAuthResponse.token_type, twitAuthResponse.access_token));
                            //webClient.Headers.Add("Content-Type", "application/json");
                            var json = webClient.DownloadString(apiRequestUri);
                            dynamic resul = JsonConvert.DeserializeObject(json);
                            userPicture = resul.profile_image_url_https;
                            _name = resul.name;
                        }
                        authenUser.id = userId;
                        authenUser.UserName = screen_username;
                        authenUser.Photo = userPicture;
                        authenUser.FirstName = _name.IndexOf(' ') != -1 ? _name.Split(' ')[0].ToString(): _name;
                        authenUser.LastName = _name.IndexOf(' ') != -1 ? _name.Split(' ')[0].ToString() : _name;
                        authenUser.Email = _name + "@" + screen_username;
                    }
                    break;
                case "LinkedIn":
                    {
                        var userId = loginInfo.ExternalIdentity.Claims.Where(c => c.Type.Equals("urn:linkedin:userid")).Select(c => c.Value).FirstOrDefault();
                        var accessToken = loginInfo.ExternalIdentity.Claims.Where(c => c.Type.Equals("urn:linkedin:accesstoken")).Select(c => c.Value).FirstOrDefault();
                        string result = string.Empty;
                        var apiRequestUri = new Uri("https://api.linkedin.com/v2/me?projection=("+ idClaim.Value + ",profilePicture(displayImage~digitalmediaAsset:playableStreams))");
                        using (var webClient = new WebClient())
                        {
                            webClient.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessToken);
                            var json = webClient.DownloadString(apiRequestUri);
                            var jo = JObject.Parse(json);
                            var elem = jo["profilePicture"]["displayImage~"]["elements"];
                            dynamic pic = elem[0]["identifiers"][0];
                            result = pic.identifier;
                        }
                        authenUser.Photo = result;
                    }
                    break;
                case "Instagram":
                    {
                        var clientId = "475904271033659";
                        var secretId = "48265387da234bad18ed3121e4fa089e";
                        string uri = "https://api.instagram.com/oauth/access_token";
                        string token = "";
                        using (var webClient = new System.Net.WebClient())
                        {
                            NameValueCollection parameters = new NameValueCollection();
                            parameters.Add("client_id", clientId);
                            parameters.Add("client_secret", secretId);
                            parameters.Add("grant_type", "authorization_code");
                            var json = webClient.UploadValues(uri, "POST", parameters);
                            var response = System.Text.Encoding.Default.GetString(json);
                            // deserializing nested JSON string to object  
                            var resul = (JObject)JsonConvert.DeserializeObject(response);
                            token = (string)resul["access_token"];
                            int id = (int)resul["user"]["id"];
                        }
                        Uri apiRequestUri = new Uri("https://graph.instagram.com/me?fields=id,username,profile_picture&access_token" + token);
                        //request profile image
                        using (var webClient = new System.Net.WebClient())
                        {
                            var json = webClient.DownloadString(apiRequestUri);
                            dynamic resul = JsonConvert.DeserializeObject(json);
                        }
                    }
                    break;
                default:
                    break;
            }

            Session["SocialLogin"] = authenUser;
            return RedirectToAction("Secured", "Home");
            //// Sign in the user with this external login provider if the user already has a login
            //var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            //switch (result)
            //{
            //    case SignInStatus.Success:
            //        return RedirectToLocal(returnUrl);
            //    case SignInStatus.LockedOut:
            //        return View("Lockout");
            //    case SignInStatus.RequiresVerification:
            //        return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
            //    case SignInStatus.Failure:
            //    default:
            //        // If the user does not have an account, then prompt the user to create an account
            //        ViewBag.ReturnUrl = returnUrl;
            //        ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
            //        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            //}
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }
        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }
        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        public ActionResult signininstagram()
        {
            var clientId = "475904271033659";
            string redirectUri = "https://localhost:44345/Account/signinInstagramCallback";
            string uri = "https://api.instagram.com/oauth/authorize/?client_id=" + clientId + "&redirect_uri=" + redirectUri + "&response_type=code&scope=basic";
            return Json(new { uri = uri });
        }
        [AllowAnonymous]
        public ActionResult signinInstagramCallback()
        {
            string code = "";
            var clientId = "475904271033659";
            var secretId = "48265387da234bad18ed3121e4fa089e";
            string redirectUri = "https://localhost:44345/Account/signinInstagramCallback";
            string uri = "https://api.instagram.com/oauth/access_token";
            string token = "";
            using (var webClient = new System.Net.WebClient())
            {
                NameValueCollection parameters = new NameValueCollection();
                parameters.Add("client_id", clientId);
                parameters.Add("client_secret", secretId);
                parameters.Add("grant_type", "authorization_code");
                parameters.Add("code", code);
                parameters.Add("redirect_uri", redirectUri);
                var json = webClient.UploadValues(uri, "POST", parameters);
                var response = System.Text.Encoding.Default.GetString(json);
                // deserializing nested JSON string to object  
                var resul = (JObject)JsonConvert.DeserializeObject(response);
                token = (string)resul["access_token"];
                int id = (int)resul["user"]["id"];
            }
            if (token == "")
            {
                return RedirectToAction("/Account/ExternalLoginFailure");
            }
            return RedirectToAction("/Home/Secured");
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }
            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }

    internal class TwitAuthenticateResponse
    {
        public string token_type { get; set; }
        public string access_token { get; set; }
    }
}