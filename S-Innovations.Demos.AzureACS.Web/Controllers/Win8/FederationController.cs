using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using S_Innovations.Security.Constants;
using S_Innovations.Security.Tokens;

namespace S_Innovations.Demos.AzureACS.Web.Controllers.Win8
{

    public class FederationController : ApiController
    {

        [Authorize]
        public Object GetProfile()
        {
            var identity = ((ClaimsIdentity)((ClaimsPrincipal)HttpContext.Current.User).Identity);
            identity.AddClaim(new Claim("OurCustomClaimType", "Hello World"));
            return identity.Claims;

        }




        [Authorize]
        public HttpResponseMessage Post()
        {

//            var token = await this.Request.Content.ReadAsFormDataAsync(); //Token, but it have already been authenticated.
            //Also using this token would be insecure, a 3th party could post a token and get it signed.
            //instead take the already authenticated ClaimsPrincipal and create a SWT token signed with info from web.config.

            
            var swttoken = ClaimsPrincipal.Current.ToSwtToken();

            var response = this.Request.CreateResponse(HttpStatusCode.Redirect);
            var tokenstring = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.WriteToken(swttoken);
            response.Headers.Add("Location", "/win8/end?" + tokenstring);           
            return response;
        }
    }
}
