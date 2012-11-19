﻿/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using S_Innovations.Security.Constants;

namespace S_Innovations.Security.Tokens
{
    
   

    public class JwtHeader
    {
        public string SignatureAlgorithm { get; set; }
        public string Type { get; set; }
        
        public SigningCredentials SigningCredentials { get; set; }

        public JwtHeader()
        {
            Type = JwtConstants.JWT;
            
        }
    }
}
