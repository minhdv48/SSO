using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using Owin.Security.Providers.LinkedIn;
using Owin.Security.Providers.Instagram;
using SocialLogin.Models;
using Owin.Security.Providers.Instagram.Provider;

namespace SocialLogin
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");
            app.UseTwitterAuthentication(
                 new Microsoft.Owin.Security.Twitter.TwitterAuthenticationOptions()
                 {
                     ConsumerKey = "yZjAVRONCLXgzXFHOuJR0BaA8",
                     ConsumerSecret = "yffpZNdRKzkdKm6WjskcROWbmN53vVCCjY34QSavdhQG346SI0",
                     Provider = new Microsoft.Owin.Security.Twitter.TwitterAuthenticationProvider
                     {
                         OnAuthenticated = (context) =>
                         {
                             context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_token", context.AccessToken));
                             context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_secret", context.AccessTokenSecret));
                             return Task.FromResult(0);
                         }
                     },
                 }
            );


            //app.UseFacebookAuthentication(
            //   appId: "1037512423795950",
            //   appSecret: "c2fe38a23ba3740c1a479022ebc81d96");

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "582395183305-tkrsnl0qkljvilfpt9pmtc02e7tuh7df.apps.googleusercontent.com",
                ClientSecret = "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",
                Provider = new GoogleOAuth2AuthenticationProvider()
                {
                    OnAuthenticated = (context) =>
                    {
                        context.Identity.AddClaim(new Claim("urn:google:name", context.Identity.FindFirstValue(ClaimTypes.Name)));
                        context.Identity.AddClaim(new Claim("urn:google:email", context.Identity.FindFirstValue(ClaimTypes.Email)));
                        //This following line is need to retrieve the profile image
                        context.Identity.AddClaim(new System.Security.Claims.Claim("urn:google:accesstoken", context.AccessToken, ClaimValueTypes.String, "Google"));

                        return Task.FromResult(0);
                    }
                }
            });
            app.UseLinkedInAuthentication(
                clientId: "86gwm1bsnxq2qu",
                clientSecret: "Id0F1Q1CTwn3CPsl"

                );
            app.UseInstagramInAuthentication(
               new InstagramAuthenticationOptions()
               {
                   ClientId = "475904271033659",
                   ClientSecret = "48265387da234bad18ed3121e4fa089e",
                   CallbackPath = new PathString("/Account/ExternalLoginCallback"),
                   SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie
               }

                );
        }
    }
}