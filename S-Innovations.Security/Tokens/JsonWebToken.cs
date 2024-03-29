﻿/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using S_Innovations.Security.Extensions;

namespace S_Innovations.Security.Tokens
{
    public class JsonWebToken : SecurityToken
    {
        private long? _expirationTime;
        private DateTime _validTo;

        private long? _notBefore;
        private DateTime _validFrom;

        #region SecurityToken
        public override string Id
        {
            get { return JwtId; }
        }

        public override System.Collections.ObjectModel.ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get
            {
                if (Header.SigningCredentials != null)
                {
                    return new ReadOnlyCollection<SecurityKey>(new List<SecurityKey> { Header.SigningCredentials.SigningKey });
                }
                else
                {
                    return new ReadOnlyCollection<SecurityKey>(new List<SecurityKey>());
                }
            }
        }

        public override DateTime ValidFrom
        {
            get { return _validFrom; }
        }

        public override DateTime ValidTo
        {
            get { return _validTo; }
        }
        #endregion

        public JwtHeader Header { get; set; }

        public long? ExpirationTime
        {
            get
            {
                return _expirationTime;
            }
            set
            {
                _expirationTime = value;
                _validTo = _expirationTime.Value.ToDateTimeFromEpoch();
            }
        }

        public long? NotBefore
        {
            get
            {
                return _notBefore;
            }
            set
            {
                _notBefore = value;
                _validFrom = _notBefore.Value.ToDateTimeFromEpoch();
            }
        }

        public long? IssuedAt { get; set; }

        public string Issuer { get; set; }
        public Uri Audience { get; set; }
        public string Principal { get; set; }
        public string JwtId { get; set; }

        public string UnsignedToken { get; set; }
        public string Signature { get; set; }

        //public List<Claim> Claims { get; set; }
        public Dictionary<string, string> Claims;


        public JsonWebToken()
        {
            Header = new JwtHeader();
            Claims = new Dictionary<string, string>();
            
            //Claims = new List<Claim>();
        }

        public void AddClaim(string type, string value)
        {
            // todo: check for reserved claim types

            if (Claims.ContainsKey(type))
            {
                // append to existing claim type
                var existing = Claims[type];
                var newValue = string.Format("{0},{1}", existing, value.Trim());

                Claims.Remove(type);
                Claims.Add(type, newValue);
            }
            else
            {
                Claims.Add(type, value);
            }
        }
    }
}
