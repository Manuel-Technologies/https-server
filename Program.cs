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
    delegate Task Middleware(HttpContext context, Func<Task> next);

    class HttpRequest
    {
        public string Method { get; init; } = "";
        public string Path { get; init; } = "";
        public string QueryString { get; init; } = "";
        public Dictionary<string, List<string>> Query { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string Body { get; init; } = "";
        public object? ParsedBody { get; init; }
        public bool KeepAlive { get; init; }
    }

    class HttpContext
    {
        public required SslStream Stream { get; init; }
        public required HttpRequest Request { get; init; }
        public Dictionary<string, object?> Items { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool ResponseStarted { get; set; }
    }

    class Program
    {
        static X509Certificate2? serverCertificate = null;
        static readonly string PublicDir = Path.Combine(Directory.GetCurrentDirectory(), "public");
        static readonly List<Middleware> MiddlewarePipeline = BuildMiddlewarePipeline();

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
                        (string path, string queryString, Dictionary<string, List<string>> query) = ParseUrl(fullUrl);

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

                        var request = new HttpRequest
                        {
                            Method = method,
                            Path = path,
                            QueryString = queryString,
                            Query = query,
                            Headers = headers,
                            Body = body,
                            ParsedBody = ParseRequestBody(headers, body),
                            KeepAlive = keepAlive
                        };

                        var context = new HttpContext
                        {
                            Stream = sslStream,
                            Request = request
                        };

                        await ExecutePipelineAsync(context);
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

        static List<Middleware> BuildMiddlewarePipeline()
        {
            return new List<Middleware>
            {
                async (context, next) =>
                {
                    Console.WriteLine($"{context.Request.Method} {context.Request.Path}");
                    await next();
                },
                async (context, next) =>
                {
                    context.Items["request.startedAt"] = DateTime.UtcNow;
                    await next();
                },
                async (context, next) =>
                {
                    if (context.Request.Method == "OPTIONS")
                    {
                        await SendResponseAsync(context, 204, "No Content", "text/plain", "", true);
                        return;
                    }

                    await next();
                },
                HandleRouteAsync
            };
        }

        static Task ExecutePipelineAsync(HttpContext context)
        {
            int index = -1;

            Task Next()
            {
                index++;
                if (index >= MiddlewarePipeline.Count || context.ResponseStarted)
                {
                    return Task.CompletedTask;
                }

                return MiddlewarePipeline[index](context, Next);
            }

            return Next();
        }

        static async Task HandleRouteAsync(HttpContext context, Func<Task> next)
        {
            HttpRequest request = context.Request;

            if (request.Method == "GET")
            {
                if (request.Path.StartsWith("/api/status"))
                {
                    var responseObj = new
                    {
                        status = "running",
                        timestamp = DateTime.UtcNow,
                        version = "1.2",
                        queryString = request.QueryString,
                        query = request.Query
                    };
                    await SendJsonResponseAsync(context, 200, "OK", responseObj);
                    return;
                }

                // Default to static files
                string staticPath = request.Path == "/" ? "/index.html" : request.Path;
                await ServeStaticFileAsync(context, staticPath);
            }
            else if (request.Method == "POST")
            {
                if (request.Path == "/api/data")
                {
                    if (request.ParsedBody is null && !string.IsNullOrWhiteSpace(request.Body))
                    {
                        await SendJsonResponseAsync(context, 400, "Bad Request", new { error = "Unsupported or invalid request body" });
                        return;
                    }

                    var responseObj = new
                    {
                        message = "Data received successfully",
                        query = request.Query,
                        receivedData = request.ParsedBody
                    };
                    await SendJsonResponseAsync(context, 200, "OK", responseObj);
                }
                else
                {
                    await SendResponseAsync(context, 404, "Not Found", "text/plain", "Not Found");
                }
            }
            else
            {
                await SendResponseAsync(context, 405, "Method Not Allowed", "text/plain", "Method Not Allowed");
            }
        }

        static (string Path, string QueryString, Dictionary<string, List<string>> Query) ParseUrl(string fullUrl)
        {
            string path = fullUrl;
            string queryString = "";
            int queryIdx = fullUrl.IndexOf('?');
            if (queryIdx >= 0)
            {
                path = fullUrl.Substring(0, queryIdx);
                queryString = fullUrl.Substring(queryIdx + 1);
            }

            return (Uri.UnescapeDataString(path), queryString, ParseQueryString(queryString));
        }

        static Dictionary<string, List<string>> ParseQueryString(string queryString)
        {
            var values = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(queryString))
            {
                return values;
            }

            foreach (string pair in queryString.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = pair.Split('=', 2);
                string key = UrlDecode(parts[0]);
                string value = parts.Length > 1 ? UrlDecode(parts[1]) : "";

                if (!values.TryGetValue(key, out List<string>? existingValues))
                {
                    existingValues = new List<string>();
                    values[key] = existingValues;
                }

                existingValues.Add(value);
            }

            return values;
        }

        static object? ParseRequestBody(Dictionary<string, string> headers, string body)
        {
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            headers.TryGetValue("Content-Type", out string? contentType);
            contentType ??= "";

            if (contentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return JsonSerializer.Deserialize<object>(body);
                }
                catch (JsonException)
                {
                    return null;
                }
            }

            if (contentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                return ParseQueryString(body);
            }

            if (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
            {
                return body;
            }

            return null;
        }

        static string UrlDecode(string value)
        {
            return Uri.UnescapeDataString(value.Replace("+", " "));
        }

        static async Task ServeStaticFileAsync(HttpContext context, string path)
        {
            string filePath = Path.Combine(PublicDir, path.TrimStart('/'));
            filePath = Path.GetFullPath(filePath);
            
            // Strong path traversal prevention
            string publicRoot = Path.GetFullPath(PublicDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!filePath.StartsWith(publicRoot, StringComparison.OrdinalIgnoreCase))
            {
                await SendResponseAsync(context, 403, "Forbidden", "text/plain", "Forbidden");
                return;
            }

            if (File.Exists(filePath))
            {
                string contentType = GetContentType(filePath);
                byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
                
                string eTag = $"\"{ComputeSha256Hash(fileBytes)}\"";
                string connectionHeader = context.Request.KeepAlive ? "keep-alive" : "close";
                
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
                await context.Stream.WriteAsync(headerBytes);
                await context.Stream.WriteAsync(fileBytes);
                await context.Stream.FlushAsync();
                context.ResponseStarted = true;
            }
            else
            {
                await SendResponseAsync(context, 404, "Not Found", "text/html", "<html><body><h1>404 Not Found</h1></body></html>");
            }
        }

        static async Task SendJsonResponseAsync(HttpContext context, int statusCode, string statusText, object data)
        {
            string json = JsonSerializer.Serialize(data);
            await SendResponseAsync(context, statusCode, statusText, "application/json", json);
        }

        static async Task SendResponseAsync(HttpContext context, int statusCode, string statusText, string contentType, string body, bool isCorsOptions = false)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string connectionHeader = context.Request.KeepAlive ? "keep-alive" : "close";
            
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
            await context.Stream.WriteAsync(headerBytes);
            await context.Stream.WriteAsync(bodyBytes);
            await context.Stream.FlushAsync();
            context.ResponseStarted = true;
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
