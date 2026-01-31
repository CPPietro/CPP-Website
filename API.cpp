#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <chrono>
#include <map>
#include <filesystem>
#include <vector>
#include <fstream>
#include <cstring>

struct HTTPRequest{
    std::string method;
    std::string path;
    std::string version;
};

HTTPRequest parseRequestLine(const std::string& request) {
    HTTPRequest req;
    
    if (request.empty()) {
        return req;
    }
    
    size_t first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos) {
        return req;
    }
    
    std::string first_line = request.substr(0, first_line_end);
    std::istringstream stream(first_line);
    stream >> req.method >> req.path >> req.version;
    
    return req;
}

// ============================================
// SECURITY: Validate filename
// ============================================
bool isValidFilename(const std::string& filename) {
    if (filename.empty()) {
        std::cerr << "Security: Empty filename\n";
        return false;
    }
    
    // Check length (prevent extremely long filenames)
    if (filename.length() > 255) {
        std::cerr << "Security: Filename too long\n";
        return false;
    }
    
    // CRITICAL: Prevent directory traversal
    if (filename.find("..") != std::string::npos) {
        std::cerr << "Security: Directory traversal attempt detected: " << filename << "\n";
        return false;
    }
    
    // Prevent path separators
    if (filename.find('/') != std::string::npos || 
        filename.find('\\') != std::string::npos) {
        std::cerr << "Security: Path separator in filename: " << filename << "\n";
        return false;
    }
    
    // Prevent null bytes (can bypass some security checks)
    if (filename.find('\0') != std::string::npos) {
        std::cerr << "Security: Null byte in filename\n";
        return false;
    }
    
    // Only allow safe characters: alphanumeric, dot, dash, underscore
    for (char c : filename) {
        bool is_alphanumeric = (c >= 'a' && c <= 'z') || 
                              (c >= 'A' && c <= 'Z') || 
                              (c >= '0' && c <= '9');
        bool is_allowed_symbol = (c == '.' || c == '-' || c == '_');
        
        if (!is_alphanumeric && !is_allowed_symbol) {
            std::cerr << "Security: Invalid character in filename: '" << c << "'\n";
            return false;
        }
    }
    
    // Prevent hidden files (starting with dot)
    if (filename[0] == '.') {
        std::cerr << "Security: Hidden file access attempt\n";
        return false;
    }
    
    return true;
}

// ============================================
// SECURITY: Extract and validate filename from path
// ============================================
std::string extractAndValidateFilename(const std::string& path) {
    // Extract filename
    size_t last_slash = path.find_last_of('/');
    if (last_slash == std::string::npos || last_slash == path.length() - 1) {
        return "";  // No filename found
    }
    
    std::string filename = path.substr(last_slash + 1);
    
    // Validate it
    if (!isValidFilename(filename)) {
        return "";  // Invalid filename
    }
    
    return filename;
}

void handleDownload(int client_socket, std::string path){
    std::string filename = extractAndValidateFilename(path);
    std::string full_path = "files/" + filename;

    std::cout << "Client is trying to download " << filename;

    if (!std::filesystem::exists(full_path)){
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    std::ifstream file(full_path, std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to open file!" << std::endl;
        std::string response = "HTTP/1.1 404 Open Error\r\nContent-Type: text/plain\r\n\r\nCannot open file";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    std::size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read all bytes into vector
    std::vector<unsigned char> file_data(file_size);
    file.read(reinterpret_cast<char*>(file_data.data()), file_size);
    
    std::string response_headers = 
        "HTTP/1.1 200 OK\r\n" 
        "Content-Type: application/octet-stream\r\n" 
        "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n" +
        "Content-Length: " + std::to_string(file_size) + "\r\n" +
        "\r\n";

        // Send headers first
    ssize_t header_bytes_sent = send(
        client_socket,                    // Socket to send to
        response_headers.c_str(),         // Pointer to data
        response_headers.length(),        // Number of bytes to send
        0                                 // Flags (0 = default behavior)
    );

    if (header_bytes_sent == -1) {
        std::cerr << "Failed to send headers: " << strerror(errno) << std::endl;
        close(client_socket);
        return;
    }

    // Send file data
    ssize_t data_bytes_sent = send(
        client_socket,                    // Socket to send to
        file_data.data(),                 // Pointer to data
        file_data.size(),                 // Number of bytes to send
        0                                 // Flags
    );

    if (data_bytes_sent == -1) {
        std::cerr << "Failed to send file data: " << strerror(errno) << std::endl;
        close(client_socket);
        return;
    }

    file.close();

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDownload";
    send(client_socket, response.c_str(), response.length(), 0);
    return;
}

void handleList(int client_socket){
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nList";
    send(client_socket, response.c_str(), response.length(), 0);
}

void handleUpload(int client_socket, std::string request){
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUpload";
    send(client_socket, response.c_str(), response.length(), 0);
}

void handleDelete(int client_socket, std::string path){
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDelete";
    send(client_socket, response.c_str(), response.length(), 0);
}

void handleHome(int client_socket){
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHome";
    send(client_socket, response.c_str(), response.length(), 0);
}

void send404(int client_socket){
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n404";
    send(client_socket, response.c_str(), response.length(), 0);
}


// ============================================
// SECURITY: Rate limiting (simple version)
// ============================================
class RateLimiter {
private:
    struct ClientInfo {
        int request_count;
        std::chrono::steady_clock::time_point last_reset;
    };
    
    std::map<std::string, ClientInfo> clients;
    const int MAX_REQUESTS_PER_MINUTE = 60;
    
public:
    bool isAllowed(const std::string& ip) {
        auto now = std::chrono::steady_clock::now();
        
        // Get or create client info
        ClientInfo& info = clients[ip];
        
        // Reset counter if a minute has passed
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - info.last_reset).count();
        
        if (elapsed >= 60) {
            info.request_count = 0;
            info.last_reset = now;
        }
        
        // Check if limit exceeded
        if (info.request_count >= MAX_REQUESTS_PER_MINUTE) {
            return false;
        }
        
        info.request_count++;
        return true;
    }
};

// Global rate limiter
RateLimiter rateLimiter;

// ============================================
// SECURITY: Validate request structure
// ============================================
bool isValidRequest(const HTTPRequest& req) {
    // Check if parsing succeeded
    if (req.method.empty() || req.path.empty() || req.version.empty()) {
        std::cerr << "Security: Malformed request\n";
        return false;
    }
    
    // Validate HTTP method
    if (req.method != "GET" && req.method != "POST" && 
        req.method != "DELETE" && req.method != "PUT" && 
        req.method != "HEAD" && req.method != "OPTIONS") {
        std::cerr << "Security: Invalid HTTP method: " << req.method << "\n";
        return false;
    }
    
    // Validate HTTP version
    if (req.version != "HTTP/1.0" && req.version != "HTTP/1.1") {
        std::cerr << "Security: Invalid HTTP version: " << req.version << "\n";
        return false;
    }
    
    // Check path length (prevent extremely long paths)
    if (req.path.length() > 2048) {
        std::cerr << "Security: Path too long\n";
        return false;
    }
    
    // Ensure path starts with /
    if (req.path.empty() || req.path[0] != '/') {
        std::cerr << "Security: Path doesn't start with /\n";
        return false;
    }
    
    return true;
}

// ============================================
// IMPROVED: Handle client with security
// ============================================
void handleClient(int client_socket, sockaddr_in client_address) {
    // SECURITY: Get client IP for logging and rate limiting
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_address.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_address.sin_port);
    
    // SECURITY: Rate limiting
    if (!rateLimiter.isAllowed(client_ip)) {
        std::cerr << "Rate limit exceeded for " << client_ip << "\n";
        std::string response = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate limit exceeded";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // SECURITY FIX: Use larger buffer or dynamic allocation
    const int BUFFER_SIZE = 8192;  // Increased from 1024
    char buffer[BUFFER_SIZE] = {0};
    
    // SECURITY FIX: Check return value of read()
    ssize_t bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read < 0) {
        std::cerr << "Error reading from socket\n";
        return;
    }
    
    if (bytes_read == 0) {
        std::cerr << "Client closed connection\n";
        return;
    }
    
    // Null-terminate to be safe
    buffer[bytes_read] = '\0';
    
    std::string request(buffer);
    
    // SECURITY: Parse and validate request
    HTTPRequest req = parseRequestLine(request);
    
    if (!isValidRequest(req)) {
        std::cerr << "Invalid request from " << client_ip << "\n";
        std::string response = "HTTP/1.1 400 Bad Request\r\n\r\nMalformed request";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // SECURITY FIX: Print IP correctly (was printing address of pointer)
    std::cout << "Received " << req.method << " " << req.path 
              << " from " << client_ip << ":" << client_port << "\n";
    
    // Route handling with security checks
    if (req.method == "GET" && req.path.find("/download/") == 0) {
        // SECURITY: Validate filename before processing
        std::string filename = extractAndValidateFilename(req.path);
        if (filename.empty()) {
            std::cerr << "Invalid filename in download request\n";
            std::string response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid filename";
            send(client_socket, response.c_str(), response.length(), 0);
            return;
        }
        handleDownload(client_socket, req.path);
    }
    else if (req.method == "POST" && req.path.find("/upload") == 0) {
        // Note: Upload validation should be in handleUpload
        handleUpload(client_socket, request);
    }
    else if (req.method == "GET" && req.path == "/list") {
        handleList(client_socket);
    }
    // SECURITY FIX: DELETE should use DELETE method, not GET
    else if (req.method == "DELETE" && req.path.find("/delete/") == 0) {
        // SECURITY: Validate filename before deleting
        std::string filename = extractAndValidateFilename(req.path);
        if (filename.empty()) {
            std::cerr << "Invalid filename in delete request\n";
            std::string response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid filename";
            send(client_socket, response.c_str(), response.length(), 0);
            return;
        }
        handleDelete(client_socket, req.path);
    }
    else if (req.method == "GET" && req.path == "/") {
        handleHome(client_socket);
    }
    else {
        send404(client_socket);
    }
}


int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);
    
    std::cout << "Server listening on port 8080\n";
    
    while (true) {
        sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        // PASS ADDRESSES of these structures (not nullptr!)
        int client_socket = accept(server_fd, (struct sockaddr*)&client_address,  &client_len);                       
        
        // Now we can access client information
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_address.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_address.sin_port);
        
        // Handle the client
        handleClient(client_socket, client_address);

        // Close the connection
        close(client_socket);
    }
    
    return 0;
}