using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using S_Innovations.Security.Constants;

namespace S_Innovations.Security.Tokens
{
    public class WebTokenIssuerTokenResolver : IssuerTokenResolver
    {
        Dictionary<string, string> _signingKeys = new Dictionary<string, string>();

 

        public WebTokenIssuerTokenResolver()
        {
            var signValue = ConfigurationManager.AppSettings[SwtConstants.SigningKeyAppSetting];
            var issureValue = ConfigurationManager.AppSettings[SwtConstants.IssureAppSetting];
            if (string.IsNullOrEmpty(signValue) || string.IsNullOrEmpty(issureValue))
                return;
            AddSigningKey(issureValue, signValue);

        }

        public void AddSigningKey(string issuer, string signingKey)
        {
            _signingKeys.Add(issuer.ToLowerInvariant(), signingKey);
             
        }


        

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = null;
            var swtClause = keyIdentifierClause as WebTokenSecurityKeyClause;
          
            string value;
            if (swtClause!=null && _signingKeys.TryGetValue(swtClause.Issuer.ToLowerInvariant(), out value))
            {
                key = new InMemorySymmetricSecurityKey(Convert.FromBase64String(value));

                return true;
            }
            return base.TryResolveSecurityKeyCore(keyIdentifierClause, out key);
           // return false;
        }


    }
}
