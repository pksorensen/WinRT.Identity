using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web;
using System.Web.Http;
using S_Innovations.Security.Tokens.Http;

namespace S_Innovations.Demos.AzureACS.Web.App_Start
{
    public class AuthenticationConfig
    {
        public static void ConfigureGlobal(HttpConfiguration globalConfig)
        {
      
            globalConfig.MessageHandlers.Add(new AuthenticationHandler());
        }

    }
}