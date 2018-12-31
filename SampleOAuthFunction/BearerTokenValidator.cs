using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SampleOAuthFunction
{
    public static class BearerTokenValidator
    {
        private static IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private static readonly string Issuer = ConfigurationManager.AppSettings["BearerTokenIssuer"]; 
        private static readonly string Audience = ConfigurationManager.AppSettings["BearerTokenAudience"];

        public static async Task Validate(HttpRequestMessage requestMessage, TraceWriter log)
        {
            var documentRetriever = new HttpDocumentRetriever { RequireHttps = Issuer.StartsWith("https://") };

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{Issuer}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever
            );

            log.Info("OAuth Validation...");
            var authHeader = requestMessage.Headers.Authorization;
            if (await ValidateTokenAsync(authHeader) == null)
            {
                log.Error("The caller is unauthorised");
                await Task.FromException(new AuthorizationException("The caller is unauthorised"));
            }
            await Task.CompletedTask;
        }

        public static async Task<ClaimsPrincipal> ValidateTokenAsync(AuthenticationHeaderValue value)
        {
            if (value?.Scheme != "Bearer")
            {
                return null;
            }

            var config = await _configurationManager.GetConfigurationAsync(CancellationToken.None);

            var validationParameter = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidAudience = Audience,
                ValidateAudience = true,
                ValidIssuer = Issuer,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys,
                RequireExpirationTime = true
            };

            ClaimsPrincipal result = null;
            var tries = 0;

            while (result == null && tries <= 1)
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    result = handler.ValidateToken(value.Parameter, validationParameter, out _);
                }
                catch (SecurityTokenSignatureKeyNotFoundException)
                {
                    // This exception is thrown if the signature key of the JWT could not be found.
                    // This could be the case when the issuer changed its signing keys, so we trigger a 
                    // refresh and retry validation.
                    _configurationManager.RequestRefresh();
                    tries++;
                }
                catch (SecurityTokenException)
                {
                    return null;
                }
            }

            return result;
        }
    }

}

