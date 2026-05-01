using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace HttpsServer
{
    class Program
    {
        static X509Certificate2? serverCertificate = null;
        static readonly string PublicDir = Path.Combine(Directory.GetCurrentDirectory(), "public");

        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting HTTPS Server...");

            try
            {
                serverCertificate = new X509Certificate2("server.pfx", "password");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading certificate: {ex.Message}");
                return;
            }

            int port = 8443;
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"Listening on https://localhost:{port}/");

            while (true)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    _ = ProcessClientAsync(client);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error accepting client: {ex.Message}");
                }
            }
        }

        static async Task ProcessClientAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using SslStream sslStream = new SslStream(client.GetStream(), false);
                    
                    var sslOptions = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = serverCertificate,
                        ClientCertificateRequired = false,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    };

                    await sslStream.AuthenticateAsServerAsync(sslOptions);

                    // Read request headers
                    var headerBytesList = new List<byte>();
                    byte[] singleByteBuffer = new byte[1];
                    while (await sslStream.ReadAsync(singleByteBuffer, 0, 1) > 0)
                    {
                        headerBytesList.Add(singleByteBuffer[0]);
                        if (headerBytesList.Count >= 4 &&
                            headerBytesList[^4] == '\r' && headerBytesList[^3] == '\n' &&
                            headerBytesList[^2] == '\r' && headerBytesList[^1] == '\n')
                        {
                            break;
                        }
                    }

                    if (headerBytesList.Count == 0) return;

                    string headersText = Encoding.UTF8.GetString(headerBytesList.ToArray());
                    string[] headerLines = headersText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                    
                    if (headerLines.Length == 0) return;

                    string requestLine = headerLines[0];
                    Console.WriteLine($"--- New Request ---");
                    Console.WriteLine(requestLine);

                    string[] requestParts = requestLine.Split(' ');
                    if (requestParts.Length < 3) return;

                    string method = requestParts[0];
                    string path = requestParts[1];

                    // Extract headers
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 1; i < headerLines.Length; i++)
                    {
                        int separatorIdx = headerLines[i].IndexOf(':');
                        if (separatorIdx > 0)
                        {
                            string key = headerLines[i].Substring(0, separatorIdx).Trim();
                            string value = headerLines[i].Substring(separatorIdx + 1).Trim();
                            headers[key] = value;
                        }
                    }

                    // Read body if Content-Length is present
                    string body = "";
                    if (headers.TryGetValue("Content-Length", out string? contentLengthStr) && int.TryParse(contentLengthStr, out int contentLength))
                    {
                        byte[] bodyBytes = new byte[contentLength];
                        int totalBytesRead = 0;
                        while (totalBytesRead < contentLength)
                        {
                            int bytesRead = await sslStream.ReadAsync(bodyBytes, totalBytesRead, contentLength - totalBytesRead);
                            if (bytesRead == 0) break;
                            totalBytesRead += bytesRead;
                        }
                        body = Encoding.UTF8.GetString(bodyBytes);
                    }

                    await HandleRouteAsync(sslStream, method, path, body);
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine($"AuthenticationException: {e.Message}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Exception: {e.Message}");
                }
            }
        }

        static async Task HandleRouteAsync(SslStream stream, string method, string path, string body)
        {
            if (method == "GET")
            {
                if (path.StartsWith("/api/status"))
                {
                    var responseObj = new { status = "running", timestamp = DateTime.UtcNow, version = "1.1" };
                    await SendJsonResponseAsync(stream, 200, "OK", responseObj);
                    return;
                }

                // Default to static files
                if (path == "/") path = "/index.html";
                await ServeStaticFileAsync(stream, path);
            }
            else if (method == "POST")
            {
                if (path == "/api/data")
                {
                    try
                    {
                        // Echo the parsed body back with an acknowledgment
                        var data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body);
                        var responseObj = new { message = "Data received successfully", receivedData = data };
                        await SendJsonResponseAsync(stream, 200, "OK", responseObj);
                    }
                    catch
                    {
                        await SendJsonResponseAsync(stream, 400, "Bad Request", new { error = "Invalid JSON payload" });
                    }
                }
                else
                {
                    await SendResponseAsync(stream, 404, "Not Found", "text/plain", "Not Found");
                }
            }
            else
            {
                await SendResponseAsync(stream, 405, "Method Not Allowed", "text/plain", "Method Not Allowed");
            }
        }

        static async Task ServeStaticFileAsync(SslStream stream, string path)
        {
            // Simple path traversal prevention
            if (path.Contains(".."))
            {
                await SendResponseAsync(stream, 403, "Forbidden", "text/plain", "Forbidden");
                return;
            }

            string filePath = Path.Combine(PublicDir, path.TrimStart('/'));
            if (File.Exists(filePath))
            {
                string contentType = GetContentType(filePath);
                byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
                
                string headers = 
                    $"HTTP/1.1 200 OK\r\n" +
                    $"Content-Type: {contentType}\r\n" +
                    "Connection: close\r\n" +
                    $"Content-Length: {fileBytes.Length}\r\n" +
                    "\r\n";
                
                byte[] headerBytes = Encoding.UTF8.GetBytes(headers);
                await stream.WriteAsync(headerBytes);
                await stream.WriteAsync(fileBytes);
                await stream.FlushAsync();
            }
            else
            {
                await SendResponseAsync(stream, 404, "Not Found", "text/html", "<html><body><h1>404 Not Found</h1></body></html>");
            }
        }

        static async Task SendJsonResponseAsync(SslStream stream, int statusCode, string statusText, object data)
        {
            string json = JsonSerializer.Serialize(data);
            await SendResponseAsync(stream, statusCode, statusText, "application/json", json);
        }

        static async Task SendResponseAsync(SslStream stream, int statusCode, string statusText, string contentType, string body)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string headers = 
                $"HTTP/1.1 {statusCode} {statusText}\r\n" +
                $"Content-Type: {contentType}; charset=UTF-8\r\n" +
                "Connection: close\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                "\r\n";

            byte[] headerBytes = Encoding.UTF8.GetBytes(headers);
            await stream.WriteAsync(headerBytes);
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
        }

        static string GetContentType(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            return ext switch
            {
                ".html" => "text/html",
                ".css" => "text/css",
                ".js" => "application/javascript",
                ".json" => "application/json",
                ".png" => "image/png",
                ".jpg" => "image/jpeg",
                ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".txt" => "text/plain",
                _ => "application/octet-stream"
            };
        }
    }
}
