using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace S_Innovations.WinRT.Identity
{
    [DataContract]
    public sealed class ACSProvider
    {
        internal IdentityManager IdentityManager
        {
            get;
            set;
        }
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0,
                                          DateTimeKind.Utc);
         

        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public string LoginUrl { get; set; }

        [DataMember]
        public string LogoutUrl { get; set; }

        [DataMember]
        public string ImageUrl { get; set; }

        public bool IsActive { get; set; }
        [DataMember]
        public string[] EmailAddressPrefixes { get; set; }

        public bool IsExpired(string swt)
        {
            if (String.IsNullOrEmpty(swt))
                return true;

            int index = swt.LastIndexOf("&ExpiresOn=");

            if (index > 0)
            {
                // Split the SWT
                swt = swt.Substring(index + 11);
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

        private string CheckForValidToken()
        {
            var vault = new Windows.Security.Credentials.PasswordVault();
            try
            {
                var cred = vault.Retrieve(IdentityManager.AccessControlNamespace, Name);
                IsActive = !IsExpired(cred.Password);
                if (!IsActive)
                    vault.Remove(cred);


                return cred.Password;

            }
            catch
            {
                IsActive = false;
                return string.Empty;
            }

        }
        private void StoreToken(string token)
        {
            var cred = new Windows.Security.Credentials.PasswordCredential(IdentityManager.AccessControlNamespace, Name, token);
            new Windows.Security.Credentials.PasswordVault().Add(cred);
        }
    }
}
