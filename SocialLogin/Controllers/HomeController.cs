using Facebook;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using SocialLogin.Models;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using System.Web.Security;

namespace SocialLogin.Controllers
{
    [RequireHttps]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        [HttpPost]
        public JsonResult FacebookLogin(string uid, string accessToken)
        {
//            dynamic me = fb.Get("me?fields=link,first_name,currency,last_name,email,gender,locale,timezone,verified,picture,age_range");
            try
            {
                if (!string.IsNullOrEmpty(accessToken))
                {
                    //get user information
                    var client = new FacebookClient(accessToken);
                    client.AppId = "1037512423795950";
                    client.AppSecret = "c2fe38a23ba3740c1a479022ebc81d96";
                    dynamic fbresult = client.Get("me?fields=id,email,first_name,last_name,picture");
                    if (fbresult == null)
                    {
                        return Json(new { success = false, url= "/Account/ExternalLoginFailure" });
                    }
                    //var id = 5679374648741242
                    string _email = fbresult.email;
                    string username = _email.Split('@')[0];
                    var authenUser = new AuthenticatedUser() { 
                        FirstName = fbresult.first_name,
                        LastName = fbresult.last_name,
                        Email = fbresult.email,
                        UserName = username,
                        Photo = fbresult.picture["data"].url
                    };
                    Session["SocialLogin"] = authenUser;
                    // set the forms auth
                    return Json(new { success = true, url = "/Home/Secured" });
                }
                return Json(new { success = false, url = "/Account/ExternalLoginFailure" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, url = "/Account/ExternalLoginFailure" });
            }
        }
        public ActionResult Secured()
        {
            AuthenticatedUser model = (AuthenticatedUser)Session["SocialLogin"];
            if(model != null)
                return View(model);
            else
                return RedirectToAction("ExternalLoginFailure", "Account");
        }
    }
}