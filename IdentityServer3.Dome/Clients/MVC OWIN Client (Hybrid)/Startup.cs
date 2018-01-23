using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sample;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(MVC_OWIN_Client.Startup))]

namespace MVC_OWIN_Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });


            //app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            //{
            //    ClientId = "mvc.owin.hybrid",
            //    Authority = "http://localhost:44111/identity",
            //    RedirectUri = "https://localhost:44300/",
            //    PostLogoutRedirectUri = "https://localhost:44300/",
            //    ResponseType = "code id_token",
            //    Scope = "openid profile read write offline_access",

            //    SignInAsAuthenticationType = "Cookies",
            //    UseTokenLifetime = false,

            //    Notifications = new OpenIdConnectAuthenticationNotifications
            //    {
            //        SecurityTokenValidated = async n =>
            //        {
            //            var dddd = n;
            //            var nid = new ClaimsIdentity(
            //                n.AuthenticationTicket.Identity.AuthenticationType,
            //                IdentityServer3.Core.Constants.ClaimTypes.GivenName,
            //                IdentityServer3.Core.Constants.ClaimTypes.Role);

            //            // get userinfo data
            //            var userInfoClient = new UserInfoClient(
            //                new Uri(Constants.UserInfoEndpoint),
            //                n.ProtocolMessage.AccessToken);

            //            var userInfo = await userInfoClient.GetAsync();
            //            userInfo.Claims.ToList().ForEach(ui => nid.AddClaim(new System.Security.Claims.Claim(ui.Item1, ui.Item2)));

            //            // keep the id_token for logout
            //            nid.AddClaim(new System.Security.Claims.Claim("id_token", n.ProtocolMessage.IdToken));

            //            // add access token for sample API
            //            nid.AddClaim(new System.Security.Claims.Claim("access_token", n.ProtocolMessage.AccessToken));

            //            // keep track of access token expiration
            //            nid.AddClaim(new System.Security.Claims.Claim("expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));

            //            // add some other app specific claim
            //            nid.AddClaim(new System.Security.Claims.Claim("app_specific", "some data"));

            //            n.AuthenticationTicket = new AuthenticationTicket(
            //                nid,
            //                n.AuthenticationTicket.Properties);
            //        },

            //        RedirectToIdentityProvider = n =>
            //        {
            //            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
            //            {
            //                var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

            //                if (idTokenHint != null)
            //                {
            //                    n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
            //                }
            //            }

            //            return Task.FromResult(0);
            //        }
            //    }
            //});


            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = "mvc.owin.hybrid",
                Authority = "http://localhost:44111/identity",
                RedirectUri = "https://localhost:44300/",
                PostLogoutRedirectUri = "https://localhost:44300/",
                ResponseType = "code id_token",
                Scope = "openid profile read write offline_access",

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                },

                SignInAsAuthenticationType = "Cookies",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                        {
                            // use the code to get the access and refresh token
                            var tokenClient = new TokenClient(
                                Constants.TokenEndpoint,
                                "mvc.owin.hybrid",
                                "secret");

                            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
                                n.Code, n.RedirectUri);

                            if (tokenResponse.IsError)
                            {
                                throw new Exception(tokenResponse.Error);
                            }

                            // use the access token to retrieve claims from userinfo
                            var userInfoClient = new UserInfoClient(
                            new Uri(Constants.UserInfoEndpoint),
                            tokenResponse.AccessToken);

                            var userInfoResponse = await userInfoClient.GetAsync();

                            // create new identity
                            var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                            id.AddClaims(userInfoResponse.GetClaimsIdentity().Claims);

                            id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                            id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
                            id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                            id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                            id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity.FindFirst("sid").Value));

                            n.AuthenticationTicket = new AuthenticationTicket(
                                new ClaimsIdentity(id.Claims, n.AuthenticationTicket.Identity.AuthenticationType, "name", "role"),
                                n.AuthenticationTicket.Properties);
                        },

                    RedirectToIdentityProvider = n =>
                        {
                            // if signing out, add the id_token_hint
                            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                            {
                                var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                                if (idTokenHint != null)
                                {
                                    n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                }

                            }

                            return Task.FromResult(0);
                        }
                }
            });
        }
    }
}