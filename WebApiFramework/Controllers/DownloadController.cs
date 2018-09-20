using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Http;

namespace WebApiFramework.Controllers
{
    public class DownloadController : ApiController
    {
        public IHttpActionResult Get()
        {
            string onlineFileLocation = @"http://go.microsoft.com/fwlink/?LinkID=521962";
            string fileName = "filename.xlsx";
            string tempFile = Path.Combine(Path.GetTempPath(), fileName);
            using (var client = new WebClient())
            {
                client.DownloadFile(onlineFileLocation, tempFile);
            }

            //converting Pdf file into bytes array  
            var dataBytes = File.ReadAllBytes(tempFile);
            //adding bytes to memory stream   
            var dataStream = new MemoryStream(dataBytes);
            return new downloadResult(dataStream, Request, fileName);

            //Code to download hte local file
            //string fileName = "SampleWorkbook.xlsx";
            //string path = @"C:\Projects\POC\ConsoleApp1\WebApiFramework";
            ////converting Pdf file into bytes array  
            //var dataBytes = File.ReadAllBytes(Path.Combine(path, fileName));
            ////adding bytes to memory stream   
            //var dataStream = new MemoryStream(dataBytes);
            //return new downloadResult(dataStream, Request, fileName);
        }

        public class downloadResult : IHttpActionResult
        {
            MemoryStream memoryStream;
            string fileName;
            HttpRequestMessage httpRequestMessage;
            HttpResponseMessage httpResponseMessage;
            public downloadResult(MemoryStream data, HttpRequestMessage request, string filename)
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
}
