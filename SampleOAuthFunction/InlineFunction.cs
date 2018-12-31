using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace SampleOAuthFunction
{
    public static class InlineFunction
    {
        [FunctionName("InlineFunction")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger function processed a request.");
            try
            {
                await BearerTokenValidator.Validate(req, log);
                // parse query parameter
                string name = req.GetQueryNameValuePairs()
                    .FirstOrDefault(q => string.Compare(q.Key, "name", true) == 0)
                    .Value;

                if (name == null)
                {
                    // Get request body
                    dynamic data = await req.Content.ReadAsAsync<object>();
                    name = data?.name;
                }

                return name == null
                    ? req.CreateResponse(HttpStatusCode.BadRequest,
                        "Please pass a name on the query string or in the request body")
                    : req.CreateResponse(HttpStatusCode.OK, "Hello " + name);
            }
            catch (AuthorizationException)
            {
                return req.CreateResponse(HttpStatusCode.Unauthorized,
                    "Unauthorized");
            }
        }
    }
}
