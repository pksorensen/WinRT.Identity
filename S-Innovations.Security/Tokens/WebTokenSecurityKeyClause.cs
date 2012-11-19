using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.Security.Tokens
{
    public class WebTokenSecurityKeyClause : SecurityKeyIdentifierClause
    {
        public string Issuer { get; set; }

        public WebTokenSecurityKeyClause(string issuer)
            : base("WebToken")
        {
            Issuer = issuer;
        }
    }
}
