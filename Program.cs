using Microsoft.VisualStudio.Services.Client;
using Microsoft.VisualStudio.Services.Common;
using Microsoft.VisualStudio.Services.WebApi;

using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

string serverUrl = args[0];
string accessToken = args[1];

VssBasicCredential basicCred = new VssBasicCredential("VstsAgent", accessToken);
VssCredentials creds = new VssCredentials(null, basicCred, CredentialPromptType.DoNotPrompt);

string[] _requiredRequestHeaders = new[]
{
    "X-TFS-Session",
    "X-VSS-E2EID",
    "User-Agent"
};

Dictionary<SslPolicyErrors, string> _sslPolicyErrorsMapping = new Dictionary<SslPolicyErrors, string>
{
    {SslPolicyErrors.None, "No SSL policy errors"},
    {SslPolicyErrors.RemoteCertificateChainErrors, "ChainStatus has returned a non empty array"},
    {SslPolicyErrors.RemoteCertificateNameMismatch, "Certificate name mismatch"},
    {SslPolicyErrors.RemoteCertificateNotAvailable, "Certificate not available"}
};

bool RequestStatusCustomValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
{
    Console.WriteLine("------------------------------");
    Console.Write(GetRequestMessage(requestMessage));
    Console.WriteLine("------------------------------");
    Console.Write(GetCertificate(certificate));
    Console.WriteLine("------------------------------");
    Console.Write(GetChain(chain));
    Console.WriteLine("------------------------------");
    Console.Write(GetSslErrors(sslErrors));
    Console.WriteLine("------------------------------");

    return (sslErrors == SslPolicyErrors.None);
}

string GetFormattedData(string diagInfoHeader, List<KeyValuePair<string, string>> diagInfo)
{
    string formattedData = $"[{diagInfoHeader}]\n";

    foreach (var record in diagInfo)
    {
        formattedData += $"{record.Key}: {record.Value}\n";
    }

    return formattedData;
}

string GetRequestMessage(HttpRequestMessage requestMessage)
{
    string requestDiagInfoHeader = "HttpRequest";
    string diagInfo = string.Empty;

    if (requestMessage is null)
    {
        return $"{requestDiagInfoHeader} data is empty";
    }

    var requestDiagInfo = new List<KeyValuePair<string, string>>();

    var requestedUri = requestMessage?.RequestUri.ToString();
    var methodType = requestMessage?.Method.ToString();
    requestDiagInfo.Add(new KeyValuePair<string, string>("Requested URI", requestedUri));
    requestDiagInfo.Add(new KeyValuePair<string, string>("Request method", methodType));

    diagInfo = GetFormattedData(requestDiagInfoHeader, requestDiagInfo);

    var requestHeaders = requestMessage?.Headers;

    if (requestHeaders is null)
    {
        return diagInfo;
    }

    string headersDiagInfoHeader = "HttpRequestHeaders";

    var headersDiagInfo = new List<KeyValuePair<string, string>>();
    foreach (var headerKey in _requiredRequestHeaders)
    {
        IEnumerable<string> headerValues;

        if (requestHeaders.TryGetValues(headerKey, out headerValues))
        {
            var headerValue = string.Join(", ", headerValues.ToArray());
            if (headerValue != null)
            {
                headersDiagInfo.Add(new KeyValuePair<string, string>(headerKey, headerValue.ToString()));
            }
        }
    }

    diagInfo += GetFormattedData(headersDiagInfoHeader, headersDiagInfo);

    return diagInfo;
}

string GetCertificate(X509Certificate2 certificate)
{
    string diagInfoHeader = "Certificate";
    var diagInfo = new List<KeyValuePair<string, string>>();

    if (certificate is null)
    {
        return $"{diagInfoHeader} data is empty";
    }

    diagInfo.Add(new KeyValuePair<string, string>("Effective date", certificate?.GetEffectiveDateString()));
    diagInfo.Add(new KeyValuePair<string, string>("Expiration date", certificate?.GetExpirationDateString()));
    diagInfo.Add(new KeyValuePair<string, string>("Issuer", certificate?.Issuer));
    diagInfo.Add(new KeyValuePair<string, string>("Subject", certificate?.Subject));

    return GetFormattedData(diagInfoHeader, diagInfo);
}

string GetChain(X509Chain chain)
{
    string diagInfoHeader = "ChainStatus";
    var diagInfo = new List<KeyValuePair<string, string>>();

    if (chain is null)
    {
        return $"{diagInfoHeader} data is empty";
    }

    foreach (var status in chain.ChainStatus)
    {
        diagInfo.Add(new KeyValuePair<string, string>("Status", status.Status.ToString()));
        diagInfo.Add(new KeyValuePair<string, string>("Status Information", status.StatusInformation));
    }

    return GetFormattedData(diagInfoHeader, diagInfo);
}

string GetSslErrors(SslPolicyErrors sslErrors)
{
    string diagInfoHeader = $"SSL Policy Errors";
    var diagInfo = new List<KeyValuePair<string, string>>();

    if (sslErrors == SslPolicyErrors.None)
    {
        diagInfo.Add(new KeyValuePair<string, string>(sslErrors.ToString(), _sslPolicyErrorsMapping[sslErrors]));
        return GetFormattedData(diagInfoHeader, diagInfo);
    }

    foreach (SslPolicyErrors errorCode in Enum.GetValues(typeof(SslPolicyErrors)))
    {
        if ((sslErrors & errorCode) != 0)
        {
            string errorValue = errorCode.ToString();
            string errorMessage = string.Empty;

            if (!_sslPolicyErrorsMapping.TryGetValue(errorCode, out errorMessage))
            {
                errorMessage = "Could not resolve related error message";
            }

            diagInfo.Add(new KeyValuePair<string, string>(errorValue, errorMessage));
        }
    }

    return GetFormattedData(diagInfoHeader, diagInfo);
}

VssClientHttpRequestSettings settings = VssClientHttpRequestSettings.Default.Clone();
settings.ServerCertificateValidationCallback = RequestStatusCustomValidation;

IEnumerable<DelegatingHandler> additionalDelegatingHandler = null;

VssConnection connection = new VssConnection(new Uri(serverUrl), new VssHttpMessageHandler(creds, settings), additionalDelegatingHandler);

await connection.ConnectAsync();

Console.WriteLine($"Authorized Identity: {connection.AuthorizedIdentity.DisplayName}");
