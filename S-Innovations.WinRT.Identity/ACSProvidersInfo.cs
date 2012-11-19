using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.WinRT.Identity
{
    public sealed class ACSProvidersInfo
    {
        public Uri IdentityProviderListUri { get; set; }

        public ACSProvider[] ACSProviderList { get; set; }
    }
}
