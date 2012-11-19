using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

namespace S_Innovations.Demos.AzureACS.Web
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            config.Routes.MapHttpRoute(
                name: "FederationApi",
                routeTemplate: "win8/{id}",
                defaults: new { controller="federation", id = RouteParameter.Optional }
            );
        }
    }
}
