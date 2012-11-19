using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Facebook;
using S_Innovations.WinRT.Identity;

namespace S_Innovations.Demos.FacebookIdentity
{
    public class FacebookIdentity : Identity
    {
        public FacebookClient _client;
        public FacebookClient Client
        {
            get
            {
                if (_client == null)
                    _client = new FacebookClient(GetClaims().First(k => k.Key == "access_token").Value);
                return _client;
            }
        }

        public Task<dynamic> GetUserInfo(object fields)
        {
            return Client.GetTaskAsync("me", fields);
        }
    }
}
