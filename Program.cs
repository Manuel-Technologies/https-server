using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;

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

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true; // Prevent process from terminating immediately
                Console.WriteLine("\nShutting down server...");
                cts.Cancel();
            };

            int port = 8443;
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"Listening on https://localhost:{port}/ (Press Ctrl+C to stop)");

            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    TcpClient client = await listener.AcceptTcpClientAsync(cts.Token);
                    _ = ProcessClientAsync(client, cts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on cancellation
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accepting client: {ex.Message}");
            }
            finally
            {
                listener.Stop();
                Console.WriteLine("Server stopped.");
            }
        }

        static async Task ProcessClientAsync(TcpClient client, CancellationToken token)
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

                    await sslStream.AuthenticateAsServerAsync(sslOptions, token);

                    bool keepAlive = true;

                    while (keepAlive && !token.IsCancellationRequested && client.Connected)
                    {
                        // Read request headers
                        var headerBytesList = new List<byte>();
                        byte[] singleByteBuffer = new byte[1];
                        
                        try 
                        {
                            while (await sslStream.ReadAsync(singleByteBuffer, 0, 1, token) > 0)
                            {
                                headerBytesList.Add(singleByteBuffer[0]);
                                if (headerBytesList.Count >= 4 &&
                                    headerBytesList[^4] == '\r' && headerBytesList[^3] == '\n' &&
                                    headerBytesList[^2] == '\r' && headerBytesList[^1] == '\n')
                                {
                                    break;
                                }
                            }
                        }
                        catch (Exception)
                        {
                            break; // Connection dropped or timeout
                        }

                        if (headerBytesList.Count == 0) break; // End of connection

                        string headersText = Encoding.UTF8.GetString(headerBytesList.ToArray());
                        string[] headerLines = headersText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        
                        if (headerLines.Length == 0) break;

                        string requestLine = headerLines[0];
                        Console.WriteLine($"--- New Request ---");
                        Console.WriteLine(requestLine);

                        string[] requestParts = requestLine.Split(' ');
                        if (requestParts.Length < 3) break;

                        string method = requestParts[0];
                        string fullUrl = requestParts[1];
                        
                        // Parse URL and Query String
                        string path = fullUrl;
                        string queryString = "";
                        int queryIdx = fullUrl.IndexOf('?');
                        if (queryIdx >= 0)
                        {
                            path = fullUrl.Substring(0, queryIdx);
                            queryString = fullUrl.Substring(queryIdx + 1);
                        }
                        path = Uri.UnescapeDataString(path);

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

                        // Determine Keep-Alive
                        keepAlive = false;
                        if (headers.TryGetValue("Connection", out string? connectionValue))
                        {
                            if (connectionValue.Contains("keep-alive", StringComparison.OrdinalIgnoreCase))
                            {
                                keepAlive = true;
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
                                int bytesRead = await sslStream.ReadAsync(bodyBytes, totalBytesRead, contentLength - totalBytesRead, token);
                                if (bytesRead == 0) break;
                                totalBytesRead += bytesRead;
                            }
                            body = Encoding.UTF8.GetString(bodyBytes);
                        }

                        await HandleRouteAsync(sslStream, method, path, queryString, body, keepAlive);
                    }
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine($"AuthenticationException: {e.Message}");
                }
                catch (OperationCanceledException)
                {
                    // Expected on graceful shutdown
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Exception: {e.Message}");
                }
            }
        }

        static async Task HandleRouteAsync(SslStream stream, string method, string path, string queryString, string body, bool keepAlive)
        {
            if (method == "OPTIONS")
            {
                await SendResponseAsync(stream, 204, "No Content", "text/plain", "", keepAlive, true);
                return;
            }

            if (method == "GET")
            {
                if (path.StartsWith("/api/status"))
                {
                    var responseObj = new { status = "running", timestamp = DateTime.UtcNow, version = "1.1", query = queryString };
                    await SendJsonResponseAsync(stream, 200, "OK", responseObj, keepAlive);
                    return;
                }

                // Default to static files
                if (path == "/") path = "/index.html";
                await ServeStaticFileAsync(stream, path, keepAlive);
            }
            else if (method == "POST")
            {
                if (path == "/api/data")
                {
                    try
                    {
                        var data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body);
                        var responseObj = new { message = "Data received successfully", receivedData = data };
                        await SendJsonResponseAsync(stream, 200, "OK", responseObj, keepAlive);
                    }
                    catch
                    {
                        await SendJsonResponseAsync(stream, 400, "Bad Request", new { error = "Invalid JSON payload" }, keepAlive);
                    }
                }
                else
                {
                    await SendResponseAsync(stream, 404, "Not Found", "text/plain", "Not Found", keepAlive);
                }
            }
            else
            {
                await SendResponseAsync(stream, 405, "Method Not Allowed", "text/plain", "Method Not Allowed", keepAlive);
            }
        }

        static async Task ServeStaticFileAsync(SslStream stream, string path, bool keepAlive)
        {
            string filePath = Path.Combine(PublicDir, path.TrimStart('/'));
            filePath = Path.GetFullPath(filePath);
            
            // Strong path traversal prevention
            if (!filePath.StartsWith(PublicDir, StringComparison.OrdinalIgnoreCase))
            {
                await SendResponseAsync(stream, 403, "Forbidden", "text/plain", "Forbidden", keepAlive);
                return;
            }

            if (File.Exists(filePath))
            {
                string contentType = GetContentType(filePath);
                byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
                
                string eTag = $"\"{ComputeSha256Hash(fileBytes)}\"";
                string connectionHeader = keepAlive ? "keep-alive" : "close";
                
                StringBuilder headers = new StringBuilder();
                headers.Append($"HTTP/1.1 200 OK\r\n");
                headers.Append($"Content-Type: {contentType}\r\n");
                headers.Append($"Connection: {connectionHeader}\r\n");
                headers.Append($"Content-Length: {fileBytes.Length}\r\n");
                headers.Append($"Cache-Control: public, max-age=3600\r\n");
                headers.Append($"ETag: {eTag}\r\n");
                headers.Append("Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
                headers.Append("X-Content-Type-Options: nosniff\r\n");
                headers.Append("X-Frame-Options: DENY\r\n");
                headers.Append("\r\n");
                
                byte[] headerBytes = Encoding.UTF8.GetBytes(headers.ToString());
                await stream.WriteAsync(headerBytes);
                await stream.WriteAsync(fileBytes);
                await stream.FlushAsync();
            }
            else
            {
                await SendResponseAsync(stream, 404, "Not Found", "text/html", "<html><body><h1>404 Not Found</h1></body></html>", keepAlive);
            }
        }

        static async Task SendJsonResponseAsync(SslStream stream, int statusCode, string statusText, object data, bool keepAlive)
        {
            string json = JsonSerializer.Serialize(data);
            await SendResponseAsync(stream, statusCode, statusText, "application/json", json, keepAlive);
        }

        static async Task SendResponseAsync(SslStream stream, int statusCode, string statusText, string contentType, string body, bool keepAlive, bool isCorsOptions = false)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string connectionHeader = keepAlive ? "keep-alive" : "close";
            
            StringBuilder headers = new StringBuilder();
            headers.Append($"HTTP/1.1 {statusCode} {statusText}\r\n");
            headers.Append($"Content-Type: {contentType}; charset=UTF-8\r\n");
            headers.Append($"Connection: {connectionHeader}\r\n");
            headers.Append($"Content-Length: {bodyBytes.Length}\r\n");
            headers.Append("Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
            headers.Append("X-Content-Type-Options: nosniff\r\n");
            headers.Append("X-Frame-Options: DENY\r\n");
            
            if (isCorsOptions)
            {
                headers.Append("Access-Control-Allow-Origin: *\r\n");
                headers.Append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
                headers.Append("Access-Control-Allow-Headers: Content-Type\r\n");
            }
            
            headers.Append("\r\n");

            byte[] headerBytes = Encoding.UTF8.GetBytes(headers.ToString());
            await stream.WriteAsync(headerBytes);
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
        }

        static string ComputeSha256Hash(byte[] rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(rawData);
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
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

