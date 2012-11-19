using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using S_Innovations.Security.Constants;
using S_Innovations.Security.Tokens;

namespace System.Security.Claims
{
    public static class ClaimsPrincipalExtensions
    {
        public static  SimpleWebToken ToSwtToken(this ClaimsPrincipal principal)
        {
            var identity = principal.Identities.First();
            var context = identity.BootstrapContext as BootstrapContext;
            var claims = identity.Claims.ToList();

            var signValue = ConfigurationManager.AppSettings[SwtConstants.SigningKeyAppSetting];
            var issureValue = ConfigurationManager.AppSettings[SwtConstants.IssureAppSetting];
            var audiencevalue = ConfigurationManager.AppSettings[SwtConstants.AudienceAppSetting];

            var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String(signValue));

            return  new SimpleWebToken(new Uri(audiencevalue),
                issureValue, context.SecurityToken.ValidTo, claims,
                key);;
        }
    }
}
