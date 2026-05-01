# Custom C# HTTPS Server

A full-fledged, low-level HTTPS server built in C# using pure sockets (`TcpListener` and `SslStream`). This project demonstrates how to handle HTTPS connections, perform TLS handshakes, and process raw HTTP requests and responses without relying on high-level frameworks like ASP.NET Core or `HttpListener`.

## Features

- **Low-Level Socket Communication:** Uses `TcpListener` for accepting raw TCP connections.
- **TLS/SSL Encryption:** Secures connections using `SslStream` and X.509 certificates.
- **Custom HTTP Routing:** Includes a basic router to handle different HTTP paths (`/`, `/about`).
- **Asynchronous Request Handling:** Efficiently handles multiple concurrent clients using `async`/`await`.
- **No External Dependencies:** Built entirely with standard .NET libraries.

## Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download) (or compatible version)
- A self-signed X.509 certificate (`.pfx` format) for local development

## Getting Started

### 1. Generate a Local Certificate

To serve HTTPS traffic locally, you need a self-signed certificate. You can generate one using PowerShell:

```powershell
# Generate a self-signed cert in the CurrentUser\My store
$cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\CurrentUser\My"

# Create a secure password
$password = ConvertTo-SecureString -String "password" -Force -AsPlainText

# Export the certificate to a .pfx file
Export-PfxCertificate -Cert $cert -FilePath "server.pfx" -Password $password
```

Ensure the generated `server.pfx` file is placed in the root directory of the project. **Note:** `server.pfx` is ignored in Git to prevent accidentally committing private keys.

### 2. Build and Run the Server

Navigate to the project directory and run the application:

```bash
dotnet run
```

The server will start listening on `https://localhost:8443/`.

### 3. Test the Endpoints

You can test the server using a web browser or `curl`. Since the certificate is self-signed, you will need to bypass certificate validation:

```bash
# Test the root path
curl.exe -k https://localhost:8443/

# Test the about page
curl.exe -k https://localhost:8443/about
```

## Architecture

1. **`TcpListener`:** Binds to `IPAddress.Any` on port `8443` and asynchronously accepts incoming TCP connections.
2. **`SslStream`:** Wraps the underlying network stream. It uses `AuthenticateAsServerAsync` along with the `.pfx` certificate to perform the TLS handshake.
3. **HTTP Parser & Router:** Reads the decrypted HTTP request from the stream, parses the request line to determine the HTTP method and path, and routes it to the appropriate handler logic.
4. **Response Generator:** Constructs a raw HTTP response string (including status line, headers, and body) and writes it back to the client.

## Security Considerations

- This project is intended for educational purposes and demonstrating low-level networking concepts in C#.
- For production environments, it is strongly recommended to use battle-tested web servers like **Kestrel** (via ASP.NET Core) which offer advanced features, performance optimizations, and security mitigations.
- Never commit private `.pfx` or `.key` files to source control.

## License

This project is open-source and available under the MIT License.
