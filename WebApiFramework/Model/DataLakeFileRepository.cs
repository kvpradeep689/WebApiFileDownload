using System.IO;
using System.Threading.Tasks;
using Microsoft.Azure.Management.DataLake.Store;

namespace EDP.Function
{
    public class DataLakeFileRepository
    {
        private readonly DataLakeConfiguration _datalakeConfiguration;
        private readonly IDataLakeStoreFileSystemManagementClient _dataLakeStoreClient;

        public DataLakeFileRepository(DataLakeConfiguration configuration, IDataLakeStoreFileSystemManagementClient dataLakeStoreClient)
        {
            _dataLakeStoreClient = dataLakeStoreClient;
            _datalakeConfiguration = configuration;
        }

        public string AccountName => _datalakeConfiguration.AccountName;

        public async Task UploadAsync(string folderPath, string fileName, Stream inputStream)
        {
            await CreateAsync(folderPath, fileName);
            await AppendAsync(folderPath, fileName, inputStream);
        }

        public async Task CreateAsync(string folderPath, string fileName)
        {
            await _dataLakeStoreClient.FileSystem.MkdirsAsync(_datalakeConfiguration.AccountName, folderPath);
            await _dataLakeStoreClient.FileSystem.CreateAsync(_datalakeConfiguration.AccountName, GetFilePath(folderPath, fileName), overwrite: true);
        }

        public async Task AppendAsync(string folderPath, string fileName, Stream inputStream)
        {
            byte[] buffer = new byte[Constants.DefaultBufferSize]; // Read in chunks of 24MB
            int bytesRead;
            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                using (var stream = new MemoryStream(buffer, 0, bytesRead))
                {
                    await _dataLakeStoreClient.FileSystem.AppendAsync(_datalakeConfiguration.AccountName, GetFilePath(folderPath, fileName), stream);
                }
            }
        }

        public async Task AppendAsync(string folderPath, string fileName, byte[] data)
        {
            using (var fileStream = new MemoryStream(data))
            {
                await AppendAsync(folderPath, fileName, fileStream);
            }
        }

        public async Task DeleteAsync(string folderPath, string fileName)
        {
            await _dataLakeStoreClient.FileSystem.DeleteAsync(_datalakeConfiguration.AccountName, GetFilePath(folderPath, fileName));
        }

        public async Task DownloadAsync(string accountName , string folderPath, string destinationPath )
        {
              _dataLakeStoreClient.FileSystem.DownloadFile(accountName, folderPath, destinationPath);
             //_dataLakeStoreClient.FileSystem.DownloadFolder(accountName, folderPath, destinationPath);

           // dataLakeStoreClient.FileSystem.DownloadFile(accountName, folderPath, destinationPath);
        }
        private static string GetFilePath(string folderPath, string fileName)
        {
            return $"{folderPath}/{fileName}";
        }
    }

    public class Constants
    {
        public const int DefaultBufferSize = 24000000;
        public const string DefaultEncodingName = "ISO-8859-1";
    }
}