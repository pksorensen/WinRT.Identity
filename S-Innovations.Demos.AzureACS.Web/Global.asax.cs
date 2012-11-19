using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using S_Innovations.Demos.AzureACS.Web.App_Start;

namespace S_Innovations.Demos.AzureACS.Web
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            AuthenticationConfig.ConfigureGlobal(GlobalConfiguration.Configuration);
            
            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            FederatedAuthentication.FederationConfigurationCreated +=
               FederatedAuthentication_FederationConfigurationCreated;

        }

        void FederatedAuthentication_FederationConfigurationCreated(object sender, System.IdentityModel.Services.Configuration.FederationConfigurationCreatedEventArgs e)
        {
            //var config=  FederatedAuthentication.FederationConfiguration.WsFederationConfiguration;
            FederatedAuthentication.WSFederationAuthenticationModule.AuthorizationFailed += WSFederationAuthenticationModule_AuthorizationFailed;
            FederatedAuthentication.WSFederationAuthenticationModule.SecurityTokenValidated += WSFederationAuthenticationModule_SecurityTokenValidated;
            FederatedAuthentication.WSFederationAuthenticationModule.RedirectingToIdentityProvider += WSFederationAuthenticationModule_RedirectingToIdentityProvider;
            FederatedAuthentication.WSFederationAuthenticationModule.SecurityTokenReceived += WSFederationAuthenticationModule_SecurityTokenReceived;
         //   FederatedAuthentication.FederationConfiguration.IdentityConfiguration
        }

        void WSFederationAuthenticationModule_SecurityTokenReceived(object sender, SecurityTokenReceivedEventArgs e)
        {
            var test = 1;
        }

        void WSFederationAuthenticationModule_RedirectingToIdentityProvider(object sender, RedirectingToIdentityProviderEventArgs e)
        {
            var test = 1;
        }

        void WSFederationAuthenticationModule_SecurityTokenValidated(object sender, SecurityTokenValidatedEventArgs e)
        {
            var test = 1;
        }

        void WSFederationAuthenticationModule_AuthorizationFailed(object sender, AuthorizationFailedEventArgs e)
        {
            var test = 1;
        }
    }
}