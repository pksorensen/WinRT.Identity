﻿using System.Web;
using System.Web.Mvc;

namespace S_Innovations.Demos.AzureACS.Web
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}