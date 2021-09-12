using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace TodoApi.Utils
{
    public class JWTAuthentication : IJWTAuthentication
    {
        public string GenerateJwtToken(string userid)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            // var tokenKey = Encoding.ASCII.GetBytes(key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, userid)}),
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddHours(3),
                IssuedAt = DateTime.UtcNow,
                Issuer = "chitsanupong",
                Audience = "public",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1234567812345678")), SecurityAlgorithms.HmacSha256Signature),
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string ValidateJwtToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("1234567812345678");
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userid = jwtToken.Claims.First(x => x.Type == "Name").Value;

                // return account id from JWT token if validation successful
                return userid;
            }
            catch
            {
                // return null if validation fails
                return null;
            }
        }
    }
}