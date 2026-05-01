using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace HttpsServer
{
    class Program
    {
        static X509Certificate2? serverCertificate = null;

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

                    // Read the HTTP request
                    byte[] buffer = new byte[8192];
                    int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    if (!string.IsNullOrEmpty(request))
                    {
                        Console.WriteLine("--- New Request ---");
                        var firstLine = request.Split('\n')[0].Trim();
                        Console.WriteLine(firstLine);

                        // Basic router
                        string responseBody = "";
                        string statusCode = "200 OK";

                        if (firstLine.StartsWith("GET / ") || firstLine.StartsWith("GET /HTTP"))
                        {
                            responseBody = "<html><body><h1>Hello from low-level C# HTTPS Server!</h1><p>You requested the root path.</p></body></html>";
                        }
                        else if (firstLine.StartsWith("GET /about "))
                        {
                            responseBody = "<html><body><h1>About Page</h1><p>This is a custom HTTPS server.</p></body></html>";
                        }
                        else
                        {
                            statusCode = "404 Not Found";
                            responseBody = "<html><body><h1>404 Not Found</h1></body></html>";
                        }

                        string response = 
                            $"HTTP/1.1 {statusCode}\r\n" +
                            "Content-Type: text/html; charset=UTF-8\r\n" +
                            "Connection: close\r\n" +
                            "Server: Custom C# HttpsServer\r\n" +
                            $"Content-Length: {Encoding.UTF8.GetByteCount(responseBody)}\r\n" +
                            "\r\n" +
                            responseBody;

                        byte[] responseBytes = Encoding.UTF8.GetBytes(response);
                        await sslStream.WriteAsync(responseBytes, 0, responseBytes.Length);
                        await sslStream.FlushAsync();
                    }
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
    }
}
