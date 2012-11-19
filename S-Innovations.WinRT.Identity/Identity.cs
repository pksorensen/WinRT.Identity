using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.WinRT.Identity
{

    public class Identity
    {
        public AuthenticationProvider Provider { get; set; }     

        public bool Success { get; internal set; }

        public string Token { get; internal set; }

        public string UnSuccessReason { get; internal set; }

        public IEnumerable<KeyValuePair<String, String>> GetClaims()
        {
            var claims = Uri.UnescapeDataString(Token).Split('&');
            return claims.Select(c =>
            {
                var claimPair = c.Split('=');
                return new KeyValuePair<String, String>(claimPair[0], claimPair[1]);
            });
        }
    }
}
