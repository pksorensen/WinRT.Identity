using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.ServiceModel.Channels;
using System.IdentityModel.Services;

namespace S_Innovations.Security.Tokens.Http
{
    public class AuthenticationHandler : DelegatingHandler
    {

        IdentityConfiguration _identityConfiguration;
        //static IdentityConfiguration _configuration;

        public IdentityConfiguration ServiceConfiguration
        {
            get
            {
                if (_identityConfiguration == null)
                    _identityConfiguration = FederatedAuthentication.FederationConfiguration.IdentityConfiguration;

                if (!_identityConfiguration.IsInitialized)
                    _identityConfiguration.Initialize();

                return _identityConfiguration;
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
        {
             
            try
            {
                var token = ExtractTokenFromHeader(request);

                if (token != null)
                {
                    
                  //  var config = new SecurityTokenHandlerConfiguration();
                  //  var t = new SecurityTokenHandlerElementCollection();

                    var principal = new ClaimsPrincipal(ServiceConfiguration.SecurityTokenHandlers.ValidateToken(token));
                   // var identities = ServiceConfiguration.SecurityTokenHandlers.ValidateToken(token);
                //    var principal = ClaimsPrincipal.CreateFromIdentities(identities);

                    request.SetUserPrincipal(principal);
                 //   request.SetUserPrincipal(principal);
                    Thread.CurrentPrincipal = principal;
                    HttpContext.Current.User = principal;
                }
            }
            catch (Exception ex)
            {

                return Task<HttpResponseMessage>.Factory.StartNew(() =>
                {
                    return new HttpResponseMessage(HttpStatusCode.Forbidden);
                });
                //throw new HttpException((int)System.Net.HttpStatusCode.Unauthorized, "The authorization header was invalid");
            }



            return base.SendAsync(request, cancellationToken);
        }
        SecurityToken ExtractTokenFromHeader(HttpRequestMessage request)
        {
            var authorizationHeader = request.Headers.Authorization;
            
            if (authorizationHeader != null && authorizationHeader.Scheme == "OAuth")
                return ServiceConfiguration.SecurityTokenHandlers[typeof(SimpleWebToken)].ReadToken(authorizationHeader.Parameter);


            return null;
        }
    }
}
