using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SocialLogin.Startup))]
namespace SocialLogin
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
