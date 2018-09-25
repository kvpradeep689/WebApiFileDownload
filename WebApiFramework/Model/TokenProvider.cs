using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace EDP.Function
{
    public interface ITokenProvider
    {
        Task<string> GetToken(IClientCredentialsConfig config);
        Task<string> GetDelegatedToken(OpenIdConnectConfig config, string targetResource, string token);
        Task<string> GetDelegatedToken(ClientCredentialsConfig config, string targetResource, string userToken);
        Task<string> GetTokenWithSecret(string authority, string resource, string clientId, string clientSecret);
        Task<string> GetTokenWithCertificate(string authority, string resource, string clientId, string certificateSubject);
        Task<string> GetTokenWithCertificate(string authority, string resource, string clientId, X509Certificate2 certificate);
    }

    public class AADTokenProvider : ITokenProvider
    {
        public async Task<string> GetToken(IClientCredentialsConfig config)
        {
            if (config.Type == CredentialType.Secret)
                return await GetTokenWithSecret(config.Authority, config.Resource, config.ClientId, config.ClientSecret);
            else
                return await GetTokenWithCertificate(config.Authority, config.Resource, config.ClientId, config.CertificateSubject);
        }

        public async Task<string> GetDelegatedToken(OpenIdConnectConfig config, string targetResource, string userToken)
        {
            if (config is null)
                throw new ArgumentNullException(nameof(config));
            if (string.IsNullOrEmpty(config.Authority))
                throw new ArgumentNullException(nameof(config.Authority));
            if (string.IsNullOrEmpty(config.ClientId))
                throw new ArgumentNullException(nameof(config.ClientId));
            if (string.IsNullOrEmpty(config.ClientSecret))
                throw new ArgumentNullException(nameof(config.ClientSecret));
            if (string.IsNullOrEmpty(targetResource))
                throw new ArgumentNullException(nameof(targetResource));
            if (string.IsNullOrEmpty(userToken))
                throw new ArgumentNullException(nameof(userToken));

            var context = new AuthenticationContext(config.Authority);
            var token = await context.AcquireTokenAsync(targetResource, new ClientCredential(config.ClientId, config.ClientSecret), new UserAssertion(userToken));
            return token.AccessToken;
        }
        public async Task<string> GetDelegatedToken(ClientCredentialsConfig config, string targetResource, string userToken)
        {
            if (config is null)
                throw new ArgumentNullException(nameof(config));
            if (string.IsNullOrEmpty(config.Authority))
                throw new ArgumentNullException(nameof(config.Authority));
            if (string.IsNullOrEmpty(config.ClientId))
                throw new ArgumentNullException(nameof(config.ClientId));
            if (string.IsNullOrEmpty(config.ClientSecret))
                throw new ArgumentNullException(nameof(config.ClientSecret));
            if (string.IsNullOrEmpty(targetResource))
                throw new ArgumentNullException(nameof(targetResource));
            if (string.IsNullOrEmpty(userToken))
                throw new ArgumentNullException(nameof(userToken));

            var context = new AuthenticationContext(config.Authority);
            var token = await context.AcquireTokenAsync(targetResource, new ClientCredential(config.ClientId, config.ClientSecret), new UserAssertion(userToken));
            return token.AccessToken;
        }

        public async Task<string> GetTokenWithSecret(string authority, string resource, string clientId, string clientSecret)
        {
            if (string.IsNullOrEmpty(authority))
                throw new ArgumentNullException(nameof(authority));
            if (string.IsNullOrEmpty(resource))
                throw new ArgumentNullException(nameof(resource));
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrEmpty(clientSecret))
                throw new ArgumentNullException(nameof(clientSecret));

            var context = new AuthenticationContext(authority);
            var token = context.AcquireTokenAsync(resource, new ClientCredential(clientId, clientSecret)).GetAwaiter().GetResult();

            return token.AccessToken;
        }

        public async Task<string> GetTokenWithCertificate(string authority, string resource, string clientId, string certificateSubject)
        {
            if (string.IsNullOrEmpty(authority))
                throw new ArgumentNullException(nameof(authority));
            if (string.IsNullOrEmpty(resource))
                throw new ArgumentNullException(nameof(resource));
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrEmpty(certificateSubject))
                throw new ArgumentNullException(nameof(certificateSubject));

            var certificate = CertificateHelper.FindCertificateBySubjectName(certificateSubject);
            return await GetTokenWithCertificate(authority, resource, clientId, certificate);
        }

        public async Task<string> GetTokenWithCertificate(string authority, string resource, string clientId, X509Certificate2 certificate)
        {
            if (string.IsNullOrEmpty(authority))
                throw new ArgumentNullException(nameof(authority));
            if (string.IsNullOrEmpty(resource))
                throw new ArgumentNullException(nameof(resource));
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (certificate is null)
                throw new ArgumentNullException(nameof(certificate));

            var context = new AuthenticationContext(authority);
            var token = await context.AcquireTokenAsync(resource, new ClientAssertionCertificate(clientId, certificate));

            return token.AccessToken;
        }
    }

    public class ClientCredentialsConfig : IClientCredentialsConfig
    {
        public CredentialType Type { get; set; }
        public string Resource { get; set; }
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string CertificateSubject { get; set; }
        public string Audience { get; set; }
        public string Tenant { get; set; }
    }

    public interface IClientCredentialsConfig
    {
        CredentialType Type { get; set; }
        string Resource { get; set; }
        string Authority { get; set; }
        string ClientId { get; set; }
        string ClientSecret { get; set; }
        string CertificateSubject { get; set; }
    }

    public enum CredentialType : byte
    {
        Secret = 0,
        Certificate = 1
    }

    public class OpenIdConnectConfig : IOpenIdConnectConfig
    {
        public string RedirectUri { get; set; }
        public string PostLogoutRedirectUri { get; set; }
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }

    public interface IOpenIdConnectConfig
    {
        string RedirectUri { get; set; }
        string PostLogoutRedirectUri { get; set; }
        string Authority { get; set; }
        string ClientId { get; set; }
        string ClientSecret { get; set; }
    }

    public class DataLakeConfiguration
    {
        public string AccountName { get; set; }
        public ClientCredentialsConfig Security { get; set; }
    }

    public static class CertificateHelper
    {
        public static X509Certificate2 FindCertificateByThumbprint(string findValue)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindByThumbprint,
                    findValue, false); // Don't validate certs, since the test root isn't installed.
                if (col == null || col.Count == 0)
                    return null;
                return col[0];
            }
            finally
            {
                store.Close();
            }
        }

        public static X509Certificate2 FindCertificateBySubjectName(string findValue)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySubjectName,
                    findValue, false); // Don't validate certs, since the test root isn't installed.
                if (col == null || col.Count == 0)
                    return null;
                return col[0];
            }
            finally
            {
                store.Close();
            }
        }

        public static X509Certificate2[] GetCertificates()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var col = store.Certificates.OfType<X509Certificate2>().ToArray();

                if (col == null || col.Length == 0)
                    return new X509Certificate2[0];
                return col;
            }
            finally
            {
                store.Close();
            }
        }
    }
}
