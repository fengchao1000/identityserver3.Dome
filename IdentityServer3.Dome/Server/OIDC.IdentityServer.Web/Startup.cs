using System.Web;
using EnhancedCoding.Samples.IdSvrServices;
using IdentityServer3.Core.Services;
using Microsoft.Owin;
using OIDC.IdentityServer.Web.Controllers;
using Owin;
using IdentityServer3.Core.Configuration;
using Serilog;
using IdentityServer3.EntityFramework;
using System.Security.Cryptography.X509Certificates;
using OIDC.IdentityServer.Web.CustomService;
using System;
using OIDC.IdentityServer.Web.Configuration;

[assembly: OwinStartup(typeof(OIDC.IdentityServer.Web.Startup))]

namespace OIDC.IdentityServer.Web
{ 
    public class Startup
    {
        public void Configuration(IAppBuilder app)   
        {
            Log.Logger = new LoggerConfiguration()
               .MinimumLevel.Debug()
               .WriteTo.File(@"c:\logs\OIDC.IdentityServer.Web.txt")
               .CreateLogger();
             
           var ef = new EntityFrameworkServiceOptions
            {
                ConnectionString = "IdSvr3Config", //配置的连接字符串，EF会自动生成数据库
            };

            var factory = new IdentityServerServiceFactory();
            factory.RegisterConfigurationServices(ef);
            factory.RegisterOperationalServices(ef);
            factory.RegisterClientStore(ef);
            factory.RegisterScopeStore(ef);

            //var factory = new IdentityServerServiceFactory()
            //       .UseInMemoryClients(Clients.Get())
            //       .UseInMemoryScopes(Scopes.Get());
            

            //自定义用户认证
            var userService = new EulaAtLoginUserService();
            factory.UserService = new Registration<IUserService>(resolver => userService);
            //自定义登录视图
            factory.ViewService = new Registration<IViewService, MvcViewService<LogonWorkflowController>>();
            //自定义登录视图,还需要这些注册，因为这些都是使用非STA处理的。
            factory.Register(new Registration<HttpContext>(resolver => HttpContext.Current));
            factory.Register(new Registration<HttpContextBase>(resolver => new HttpContextWrapper(resolver.Resolve<HttpContext>())));
            factory.Register(new Registration<HttpRequestBase>(resolver => resolver.Resolve<HttpContextBase>().Request));
            factory.Register(new Registration<HttpResponseBase>(resolver => resolver.Resolve<HttpContextBase>().Response));
            factory.Register(new Registration<HttpServerUtilityBase>(resolver => resolver.Resolve<HttpContextBase>().Server));
            factory.Register(new Registration<HttpSessionStateBase>(resolver => resolver.Resolve<HttpContextBase>().Session));

            var options = new IdentityServerOptions
            {
                SiteName = "认证中心",
                SigningCertificate = Certificate.Load(),
                Factory = factory,
                RequireSsl = false,
                 AuthenticationOptions = new AuthenticationOptions
                 {
                     IdentityProviders = ConfigureAdditionalIdentityProviders,
                     LoginPageLinks = new LoginPageLink[] {
                            new LoginPageLink{
                                Text = "Register",
                                //Href = "~/localregistration"
                                Href = "localregistration"
                            }
                        }
                 },

                EventsOptions = new EventsOptions
                {
                    RaiseSuccessEvents = true,
                    RaiseErrorEvents = true,
                    RaiseFailureEvents = true,
                    RaiseInformationEvents = true
                }
            };

            //启动清除过期票据定时器
            var cleanToken = new TokenCleanup(ef, 20);
            cleanToken.Start();

            //自定义服务路径 http://localhost:44111/identity
            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(options);
            });

            Log.Logger.Information("程序启动成功");
        }

        X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(
                string.Format(@"{0}\bin\identityServer\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }

        public static void ConfigureAdditionalIdentityProviders(IAppBuilder app, string signInAsType)
        {
             
        }
    }
}