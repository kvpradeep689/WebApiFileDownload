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
using System.Threading;
using System.Threading.Tasks;
using System.Web;
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
    public class AESController : ApiController
    {
        private static string Authority = "https://login.microsoftonline.com/2b31fc5d-74fe-49df-a518-ae15aef09e70";
        private static string applicationId = "0cf16a24-3907-4656-833e-50140de1ba3e";     // Also called client id
        private static string clientSecret = "X7Lv+ZFN1ipXpp2ld54fHir7X12TxPr3myjcQGbfryI=";
        private static string adlsAccountFQDN = "https://datalake.azure.net/";
        //private static string fileName = "Encrypt.txt";

        private static string Desttemppath = Path.GetTempFileName();//Path.Combine(Path.GetTempPath(), Path.GetT);

        private static string TempFolderPath = Path.GetTempPath();
       // private static string filepath = "//dlsmgdev6t6edp06.azuredatalakestore.net/raw/ocdb/pii/party_individual/ocdb/party_individual/monthlist.xlsx";
        private static string filepath = "";//"/raw/MyFile-encrypted.txt";
       // private static string privatekeytoken = HostingEnvironment.MapPath(@"~/privatekeytoken.txt");
        private static string ADLSstorename = "";//"dlsmgdev6t6edp06";
 
        private static string PlainFilename = HostingEnvironment.MapPath(@"~/MyFile-decrypted.txt");

       // private static string filepathEncrypted = HostingEnvironment.MapPath(@"~/MyFile-Encrypted.csv");
      //  private static string filepathDecrypted = HostingEnvironment.MapPath(@"~/MyFile-decrypted.csv");
       // private static string Decryptpassword = "qwertyuiopasdfghjklzxcvbnmqwert";

        public IHttpActionResult Get([FromUri] string uri)
        {
            HttpContext.Current.Server.ScriptTimeout = 30 * 60; //30 minutes
            try
            {
                SetFileAccessSettings(uri);
                GetLakeRepository().Wait();
                var dataBytes = File.ReadAllBytes(PlainFilename);
                //adding bytes to memory stream   
                var dataStream = new MemoryStream(dataBytes);
                return new DownloadResult(dataStream, Request, PlainFilename);
                //return null;


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
            PlainFilename = HostingEnvironment.MapPath(filepath.Substring(filepath.LastIndexOf('/') + 1));
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
                Dec(Desttemppath, PlainFilename);
                  
              
             
                               
                return lakeRepo;
            }
            catch (Exception ex)
            {
                var message = ex.Message;

                throw;
            }
        }
      

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

        //private static void Enc(string decryptedFileName, string encryptedFileName)
        //{
        //    const int chunkSize = 1024;
        //    PasswordDeriveBytes passwordDB = new PasswordDeriveBytes("ThisIsMyPassword", Encoding.ASCII.GetBytes("thisIsMysalt!"), "MD5", 2);
        //    byte[] passwordBytes = passwordDB.GetBytes(128 / 8);

        //    using (FileStream fsOutput = File.OpenWrite(encryptedFileName))
        //    {
        //        using (FileStream fsInput = File.OpenRead(decryptedFileName))
        //        {
        //            byte[] IVBytes = Encoding.ASCII.GetBytes("1234567890123456");

        //            fsOutput.Write(BitConverter.GetBytes(fsInput.Length), 0, 8);
        //            fsOutput.Write(IVBytes, 0, 16);

        //            RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.ANSIX923 };
        //            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(passwordBytes, IVBytes);

        //            using (CryptoStream cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
        //            {
        //                for (long i = 0; i < fsInput.Length; i += chunkSize)
        //                {
        //                    byte[] chunkData = new byte[chunkSize];
        //                    int bytesRead = 0;
        //                    while ((bytesRead = fsInput.Read(chunkData, 0, chunkSize)) > 0)
        //                    {
        //                        if (bytesRead != 16)
        //                        {
        //                            for (int x = bytesRead - 1; x < chunkSize; x++)
        //                            {
        //                                chunkData[x] = 0;
        //                            }
        //                        }
        //                        cryptoStream.Write(chunkData, 0, chunkSize);
        //                    }
        //                }
        //                cryptoStream.FlushFinalBlock();
        //            }
        //        }
        //    }
        //}

        private static void Dec(string encryptedFileName, string decryptedFileName)
        {
            const int chunkSize = 1024;
            PasswordDeriveBytes passwordDB = new PasswordDeriveBytes("ThisIsMyPassword", Encoding.ASCII.GetBytes("thisIsMysalt!"), "MD5", 2);
            byte[] passwordBytes = passwordDB.GetBytes(128 / 8);

            using (FileStream fsInput = File.OpenRead(encryptedFileName))
            {
                using (FileStream fsOutput = File.OpenWrite(decryptedFileName))
                {
                    byte[] buffer = new byte[8];
                    fsInput.Read(buffer, 0, 8);

                    long fileLength = BitConverter.ToInt64(buffer, 0);

                    byte[] IVBytes = new byte[16];
                    fsInput.Read(IVBytes, 0, 16);


                    RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.ANSIX923 };
                    ICryptoTransform decryptor = symmetricKey.CreateDecryptor(passwordBytes, IVBytes);

                    using (CryptoStream cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                    {
                        for (long i = 0; i < fsInput.Length; i += chunkSize)
                        {
                            byte[] chunkData = new byte[chunkSize];
                            int bytesRead = 0;
                            while ((bytesRead = fsInput.Read(chunkData, 0, chunkSize)) > 0)
                            {
                                cryptoStream.Write(chunkData, 0, bytesRead);
                            }
                        }
                    }
                }
            }
        }

        
    }
}










