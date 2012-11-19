using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.Security.Constants
{
    public static class SwtConstants
    {
        public const string SigningKeyAppSetting = "SwtSigningKey";
        public const string IssureAppSetting = "SwtIssure";
        public const string AudienceAppSetting = "SwtAudience";

        public const string SWT = "SWT";

        public const string Audience = "Audience";
        public const string ExpiresOn = "ExpiresOn";
        public const string Issuer = "Issuer";
        public const string Digest256 = "HMACSHA256";
    }
}
