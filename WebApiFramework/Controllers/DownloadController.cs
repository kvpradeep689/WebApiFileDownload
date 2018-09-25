using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Hosting;
using System.Web.Http;
using System.Web.Http.Results;
using EDP.Function;
using Microsoft.Azure.DataLake.Store;
using Microsoft.Azure.Management.DataLake.Store;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure.Authentication;

namespace WebApiFramework.Controllers
{
    public class DownloadController : ApiController
    {
        private static string Authority = "https://login.microsoftonline.com/2b31fc5d-74fe-49df-a518-ae15aef09e70";
        private static string applicationId = "0cf16a24-3907-4656-833e-50140de1ba3e";     // Also called client id
        private static string clientSecret = "X7Lv+ZFN1ipXpp2ld54fHir7X12TxPr3myjcQGbfryI=";
        private static string adlsAccountFQDN = "https://datalake.azure.net/";
        //private static string fileName = "Encrypt.txt";

        private static string Desttemppath = Path.GetTempFileName();//Path.Combine(Path.GetTempPath(), Path.GetT);
       // private static string filepath = "//dlsmgdev6t6edp06.azuredatalakestore.net/raw/ocdb/pii/party_individual/ocdb/party_individual/monthlist.xlsx";
        private static string filepath = "";//"/raw/MyFile-encrypted.txt";
        private static string privatekeytoken = HostingEnvironment.MapPath(@"~/privatekeytoken.txt");
        private static string ADLSstorename = "";//"dlsmgdev6t6edp06";
        private static string PlainFilename = HostingEnvironment.MapPath(@"~/MyFile-decrypted.txt");

        public IHttpActionResult Get([FromUri] string uri)
        {
            try
            {
                SetFileAccessSettings(uri);
                GetLakeRepository().Wait();

                var dataBytes = File.ReadAllBytes(PlainFilename);
                //adding bytes to memory stream   
                var dataStream = new MemoryStream(dataBytes);
                return new DownloadResult(dataStream, Request, "DecryptedFile.txt");


            }
            catch (AdlsException e)
            {
                PrintAdlsException(e);
                return new InternalServerErrorResult(Request);
            }
        }

        private void SetFileAccessSettings(string uri)
        {
            //uri=adl://dlsmgdev6t6edp06.azuredatalakestore.net/raw/Teste.txt
            var splitValues = uri.Split(new [] {".azuredatalakestore.net"}, StringSplitOptions.None);
            ADLSstorename = splitValues[0].Substring(splitValues[0].IndexOf("adl://") + 6);
            filepath = splitValues[1];
        }

        private async static Task<DataLakeFileRepository> GetLakeRepository()
        {
            try
            {
                var tokenProvider = new AADTokenProvider();

                var lakeConfig = new DataLakeConfiguration()
                {
                    AccountName = ADLSstorename,
                    Security = new ClientCredentialsConfig()
                    {
                        Audience = adlsAccountFQDN,
                        Authority = Authority,
                        ClientId = applicationId,
                        ClientSecret = clientSecret,
                        Resource = adlsAccountFQDN,
                        Type = CredentialType.Secret
                    }
                };

                var lakeClient = new DataLakeStoreFileSystemManagementClient(await GetCredentials(lakeConfig.Security, tokenProvider));

                var lakeRepo = new DataLakeFileRepository(lakeConfig, lakeClient);
                Desttemppath = Path.GetTempFileName();
                File.Delete(Desttemppath);
                await lakeRepo.DownloadAsync(ADLSstorename, filepath, Desttemppath);

                Decrypt(privatekeytoken, Desttemppath, PlainFilename);
                
                


                return lakeRepo;
            }
            catch (Exception ex)
            {
                var message = ex.Message;

                throw;
            }
        }

        static void Decrypt(string privateKeyFileName, string encryptedFileName, string plainFileName)
        {
            // Variables

            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamReader privateKeyFile = null;
            FileStream encryptedFile = null;
            StreamWriter plainFile = null;
            string privateKeyText = "";
            string plainText = "";
            byte[] encryptedBytes = null;
            byte[] plainBytes = null;
            try
            {
                // Select target CSP
                cspParams = new CspParameters();
                cspParams.ProviderType = 1; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name

                rsaProvider = new RSACryptoServiceProvider(cspParams);
                // Read private/public key pair from file
                //privateKeyFile = File.OpenText(@"C:\data\privatekeytoken.txt");
                privateKeyFile = File.OpenText(privateKeyFileName);
                privateKeyText = privateKeyFile.ReadToEnd();
                // Import private/public key pair
                rsaProvider.FromXmlString((privateKeyText));
                // Read encrypted text from file
                // encryptedFile = File.OpenRead(@"C:\data\MyFile-encrypted.txt");
                encryptedFile = File.OpenRead(encryptedFileName);
                encryptedBytes = new byte[encryptedFile.Length];
                encryptedFile.Read(encryptedBytes, 0, (int)encryptedFile.Length);

                // Decrypt text
                plainBytes = rsaProvider.Decrypt(encryptedBytes, false);
                // Write decrypted text to file

                //plainFile = File.CreateText(@"C:\data\MyFile-decrypted.txt");
                plainFile = File.CreateText(plainFileName);
                plainText = Encoding.Unicode.GetString(plainBytes);
                plainFile.Write(plainText);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception decrypting file! More info:");
                Console.WriteLine(ex.Message);
            }

            finally
            {
                // Do some clean up if needed

                if (privateKeyFile != null)
                {
                    privateKeyFile.Close();
                }
                if (encryptedFile != null)
                {
                    encryptedFile.Close();
                }
                if (plainFile != null)
                {
                    plainFile.Close();
                }

            }
        } // Decrypt

        private static async Task<Microsoft.Rest.ServiceClientCredentials> GetCredentials(IClientCredentialsConfig config, ITokenProvider tokenProvider)
        {
            try
            {
                var token = await tokenProvider.GetToken(config);
                return new Microsoft.Rest.TokenCredentials(token);
            }
            catch (Exception ex)
            {
                var message = ex.Message;
                //log.Error(message);
                throw;
            }
        }
        private static void PrintAdlsException(AdlsException exp)

        {

            Console.WriteLine("ADLException");

            Console.WriteLine($"   Http Status: {exp.HttpStatus}");

            Console.WriteLine($"   Http Message: {exp.HttpMessage}");

            Console.WriteLine($"   Remote Exception Name: {exp.RemoteExceptionName}");

            Console.WriteLine($"   Server Trace Id: {exp.TraceId}");

            Console.WriteLine($"   Exception Message: {exp.Message}");

            Console.WriteLine($"   Exception Stack Trace: {exp.StackTrace}");

            Console.WriteLine();

        }



   
    }

    public class DownloadResult : IHttpActionResult
    {
        MemoryStream memoryStream;
        string fileName;
        HttpRequestMessage httpRequestMessage;
        HttpResponseMessage httpResponseMessage;
        public DownloadResult(MemoryStream data, HttpRequestMessage request, string filename)
        {
            memoryStream = data;
            httpRequestMessage = request;
            fileName = filename;
        }
        public Task<HttpResponseMessage> ExecuteAsync(System.Threading.CancellationToken cancellationToken)
        {
            httpResponseMessage = httpRequestMessage.CreateResponse(HttpStatusCode.OK);
            httpResponseMessage.Content = new StreamContent(memoryStream);
            httpResponseMessage.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment");
            httpResponseMessage.Content.Headers.ContentDisposition.FileName = fileName;
            httpResponseMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

            return Task.FromResult(httpResponseMessage);
        }
    }

}
