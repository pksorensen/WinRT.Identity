using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.Security.Tokens
{
    public class WebTokenIssuerNameRegistry : ConfigurationBasedIssuerNameRegistry
    {
        //Dictionary<string, string> _allowedIssuers = new Dictionary<string, string>();

        //public void AddTrustedIssuer(string issuerUri, string issuerName)
        //{
        //    _allowedIssuers.Add(issuerUri.ToLowerInvariant(), issuerName.ToLowerInvariant());
        //}

        public override string GetIssuerName(SecurityToken securityToken)
        {
            var swt = securityToken as SimpleWebToken;
            if (swt != null)
            {
          
                if (ConfiguredTrustedIssuers.Values.Contains(swt.Issuer.ToLowerInvariant()))
                {
                    return swt.Issuer;
                }
            }

            var jwt = securityToken as JsonWebToken;
            if (jwt != null)
            {                                   
                if (ConfiguredTrustedIssuers.Values.Contains(jwt.Issuer.ToLowerInvariant()))
                {
                    return jwt.Issuer;
                }
            }

            return base.GetIssuerName(securityToken);
        }
    }
}
