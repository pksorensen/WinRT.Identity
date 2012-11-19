using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using S_Innovations.WinRT.Identity;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Authentication.Web;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace S_Innovations.Demos.AzureACS.Win8StoreApp
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// Invoked when this page is about to be displayed in a Frame.
        /// </summary>
        /// <param name="e">Event data that describes how this page was reached.  The Parameter
        /// property is typically used to configure the page.</param>
        protected override async void OnNavigatedTo(NavigationEventArgs e)
        {
            Uri callbackUri = Windows.Security.Authentication.Web.WebAuthenticationBroker.GetCurrentApplicationCallbackUri();


     
    //        string realm = "http://77.75.160.102:3615/";
    //        string replyto = "http://77.75.160.102:3615/win8/";
    //        //https://s-innovations.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm=http://77.75.160.102:3615/win8/
    //        var t = new Uri("https://s-innovations.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm=" + Uri.EscapeUriString(realm) + "&wreply=" + Uri.EscapeUriString(replyto));

    //        WebAuthenticationResult webAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
    //WebAuthenticationOptions.None, 
    //new Uri("https://s-innovations.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm="+ Uri.EscapeUriString(realm) +"&wreply="+ Uri.EscapeUriString(replyto) ),
    //new Uri("http://77.75.160.102:3615/win8/end"));

    //        var token = webAuthenticationResult.ResponseData.Split('?')
    //.Single(v => v.StartsWith("acsToken=", StringComparison.OrdinalIgnoreCase))
    //.Replace("acsToken=", "");

    //        HttpClient client = new HttpClient();
    //        client.DefaultRequestHeaders.Authorization =
    //            new AuthenticationHeaderValue("OAuth", token);
           
    //        string response = await client.GetStringAsync("http://77.75.160.102:3615/win8/");

           
        }

        private async void Button_Click_1(object sender, RoutedEventArgs e)
        {
            if (ProviderSelection.DataContext == null)
                ProviderSelection.DataContext = await App.IdentityService.GetACSProviderAsync();
            else
            {
                var provider = ProviderSelection.SelectedItem as ACSProvider;
                var identity = await App.IdentityService.IdentifyAsync(AuthenticationProvider.AzureControlService,
                    provider);
                OutputText.Text = string.Join("\n", identity.GetClaims().Select(c =>
                    string.Format("{0}:{1}\n", c.Key, c.Value)));

                var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("OAuth", identity.Token);

                string response = await client.GetStringAsync("http://77.75.160.102:3615/win8/");
                OutputText.Text += response;
 

            }
        }

        private async void Button_Click_2(object sender, RoutedEventArgs e)
        {
            var identity = await App.IdentityService.IdentifyAsync
                (AuthenticationProvider.AzureControlService);
            OutputText.Text = string.Join("\n", identity.GetClaims().Select(c =>
                string.Format("{0}:{1}\n", c.Key, c.Value)));
        }

        private async void Button_Click_3(object sender, RoutedEventArgs e)
        {
            var result = await App.IdentityService.IdentifyAsync<S_Innovations.Demos.FacebookIdentity.FacebookIdentity>(
              WinRT.Identity.AuthenticationProvider.Facebook);
            var userinfo = await result.GetUserInfo(new { fields = "name,id" });

            OutputText.Text = "Name:" + userinfo.name + "\nId:" + userinfo.id;

        }

       
    }
}
