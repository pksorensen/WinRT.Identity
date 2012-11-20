using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;

namespace S_Innovations.WinRT.Identity
{

    public enum AuthenticationProvider
    {
        AzureControlService = 0,
        Facebook = 1,
    }

    public sealed class IdentityManager
    {
        private const string ACS_Providers_Feed = "https://{0}.accesscontrol.windows.net/v2/metadata/IdentityProviders.js?protocol=wsfederation&realm={1}&reply_to={2}&context=&request_id=&version=1.0&callback=";
        private const string ACS_Login_Feed = "https://{0}.accesscontrol.windows.net:443/v2/wsfederation?wa=wsignin1.0&wtrealm={1}&wreply={2}";
        private const string Facebook_Login_Feed = "https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&scope=read_stream&display=popup&response_type=token";
        private const string Facebook_LoginSucces = "https://www.facebook.com/connect/login_success.html";
       
   
        /// <summary>
        /// Azure ACS Properties
        /// </summary>
        public string AccessControlNamespace { get; set; }
        public string Realm { get; set; }
        public string BouncerReplyUrl { get; set; }
        
        /// <summary>
        /// Facebook Properties
        /// </summary>
        public string FacebookApplicationID { get; set; }
        public string FacebookApplicationSecret { get; set; }

        public bool UsePasswordVault { get; set; }


        private Lazy<Task<ACSProvidersInfo>> _fetcher;

        public Task<ACSProvidersInfo> GetACSProviderAsync(Boolean ReFetch = false)
        {
            if(ReFetch || _fetcher == null)
                _fetcher = _fetcher = new Lazy<Task<ACSProvidersInfo>>(
                    (Func<Task<ACSProvidersInfo>>)_GetACSProvidersAsync);

            return _fetcher.Value;
        }
        private async Task<ACSProvidersInfo> _GetACSProvidersAsync()
        {
            if (string.IsNullOrEmpty(AccessControlNamespace))
              throw new ArgumentNullException("AccessControlNamespace");
            if (string.IsNullOrEmpty(Realm))
              throw new ArgumentNullException("Realm");
            if (string.IsNullOrEmpty(BouncerReplyUrl))
              throw new ArgumentNullException("BouncerReplyUrl");
       

                HttpClient client = new HttpClient();
                var feedUri = new Uri(string.Format(ACS_Providers_Feed,
                    this.AccessControlNamespace,
                    Uri.EscapeUriString(this.Realm),
                    Uri.EscapeUriString(this.BouncerReplyUrl)));
                ACSProvider[] providerlist = null;
                try
                {
                    var response = await client.GetAsync(feedUri);
                    var serializer = new DataContractJsonSerializer(typeof(IEnumerable<ACSProvider>));
                    providerlist = (serializer.ReadObject(response.Content.ReadAsStreamAsync().Result)
                        as IEnumerable<ACSProvider>).Select(p =>
                            {
                                p.IdentityManager = this;
                                return p;
                            }).ToArray();
                }
                catch (Exception ex)
                {
                    return null;
                }
                return new ACSProvidersInfo { ACSProviderList = providerlist, IdentityProviderListUri = feedUri };
                
        }

        public async Task<IEnumerable<KeyValuePair<string,string>>> GetValidTokensAsync()
        {
            var vault = new Windows.Security.Credentials.PasswordVault();
            var tokens = vault.FindAllByResource(AccessControlNamespace);
            var providers = await GetACSProviderAsync();
            
            return tokens.Where( c=> 
                !providers.ACSProviderList.First(p=>p.Name == c.UserName).IsExpired(c.Password)
                 ).Select(c => new KeyValuePair<string,string>(c.UserName,c.Password));
            
        }
        public Task<Identity> IdentifyAsync(AuthenticationProvider provider, ACSProvider ACSProvider = null)
        {
            return IdentifyAsync<Identity>(provider, ACSProvider);
        }
        public async Task<T> IdentifyAsync<T>(AuthenticationProvider provider, ACSProvider ACSProvider = null) where T : Identity, new()
        {
            var vault = new Windows.Security.Credentials.PasswordVault();

            try
            {

                var tok = vault.Retrieve(AccessControlNamespace, provider.ToString());
                if (IsExpired(tok.Password))
                {
                    vault.Remove(tok);
                }
                else
                {
                    return new T() { Token = tok.Password, Success = true, Provider = provider };
                }
            }
            catch (Exception ex)
            {

            }
 

            string LoginUrl="";
            string BouncerEndUrl="";

            switch (provider)
            {
                case AuthenticationProvider.AzureControlService:
                    if (ACSProvider != null)
                    {
                        LoginUrl = ACSProvider.LoginUrl;
                        
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(AccessControlNamespace))
                            throw new ArgumentNullException("AccessControlNamespace");
                        if (string.IsNullOrEmpty(Realm))
                            throw new ArgumentNullException("Realm");
                        if (string.IsNullOrEmpty(BouncerReplyUrl))
                            throw new ArgumentNullException("BouncerReplyUrl");
                        LoginUrl = string.Format(ACS_Login_Feed,
                            AccessControlNamespace,
                            Realm, BouncerReplyUrl);
                        

                    }
                    BouncerEndUrl = BouncerReplyUrl + "end";
                    break;
                case AuthenticationProvider.Facebook:
                        LoginUrl = string.Format(Facebook_Login_Feed,
                            Uri.EscapeDataString(FacebookApplicationID),
                            Uri.EscapeDataString(Facebook_LoginSucces));
                        BouncerEndUrl = Facebook_LoginSucces;
                    break;
            }


            return await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.None,
                    new Uri(LoginUrl),
                    new Uri(BouncerEndUrl)).AsTask<WebAuthenticationResult>()
                    .ContinueWith < T>(t =>
                    {
                        var response = t.Result;
                        if (!t.IsFaulted && (response.ResponseStatus == WebAuthenticationStatus.Success))
                        {
                            string token = response.ResponseData;// response.ResponseData.Substring(response.ResponseData.IndexOf('=') + 1);
                            token = token.Replace(BouncerEndUrl, "").Substring(1); //Assume that the url is the BouncerEndUrl + '#' / '?' + claims.

                            if (provider == AuthenticationProvider.Facebook)
                            {
                                var idx = token.IndexOf("&expires_in=");
                                var time = int.Parse(token.Substring(idx+12));
                                token = token.Insert(idx, string.Format("&ExpiresOn={0}", (int)DateTime.UtcNow.Add(TimeSpan.FromSeconds(time)).Subtract(Epoch).TotalSeconds));


                            }

                            if (UsePasswordVault)
                            {
                                var cred = new Windows.Security.Credentials.PasswordCredential(AccessControlNamespace,
                                   provider.ToString(), token);
                                new Windows.Security.Credentials.PasswordVault().Add(cred);

                            }
                            return new T() { Token = token, Success = true, Provider = provider };
                        
                        
                        }
                        else
                            return new T() { UnSuccessReason = response.ResponseStatus.ToString(),
                                Success = false, Provider = provider };
                    });

           

        }
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0,
                                  DateTimeKind.Utc);

        public bool IsExpired(string swt)
        {
            if (String.IsNullOrEmpty(swt))
                return true;

            int index = swt.LastIndexOf("&ExpiresOn="); int lenght = 11;
            //if (index == -1)
            //{
            //    index = swt.LastIndexOf("&expires_in=");
            //    lenght = 12;
            //}

            if (index > 0)
            {
                // Split the SWT
                swt = swt.Substring(index + lenght);
                index = swt.IndexOf('&');

                if (index > 0)
                {
                    // Remove everything after the expiration timestamp
                    swt = swt.Substring(0, index);
                    // Convert the timestamp and compare against the current (UTC) time
                    double seconds = double.Parse(swt, CultureInfo.InvariantCulture);

                    return DateTime.UtcNow > Epoch.AddSeconds(seconds);

                }
            }

            return false;
        }
    
        public IdentityManager()
        {

        }

    }
}
