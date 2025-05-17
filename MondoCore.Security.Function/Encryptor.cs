using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using MondoCore.Security.Encryption;
using System.Text;

namespace MondoCore.Security.Function
{
    public class Encryptor(IEncryptor encryptor)
    {
        [Function("Encrypt")]
        public async Task<IActionResult> Encrypt([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req)
        {
            var payload = await GetPayload(req);
            var result  = await encryptor.EncryptString(payload);

            return new OkObjectResult(result);
        }

        [Function("Decrypt")]
        public async Task<IActionResult> Decrypt([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req)
        {
            var payload = await GetPayload(req);
            var result  = await encryptor.DecryptString(payload);

            return new OkObjectResult(result);
        }

        private async Task<string> GetPayload(HttpRequest req)
        {
            var result = await (new StreamReader(req.Body)).ReadToEndAsync();

            if(string.IsNullOrEmpty(result))
                throw new ArgumentException("Payload is empty");

            return result;
        }
    }
}
