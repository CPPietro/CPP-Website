
// All of the includes neccesary
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
#include <algorithm>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <thread>
#include <atomic>

// Structure for the HTTP requests recived, used in parsing
struct HTTPRequest{
    std::string method;
    std::string path;
    std::string version;
};

// List of allowed file extensions for upload
std::vector<std::string> allowed_extensions = {
        ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", 
        ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip"
    };

// Function that reads and opens a HTML file from the param path
// E.G. "html/home.html"
std::string readHtmlFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "<html><body><h1>Error: Could not load page</h1></body></html>";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Function that parses the request line of a recieved HTTP request
// Will return the HTTP request structure
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

// Helper function to convert a string to lowercase 
std::string to_lowercase(std::string target){
    std::string new_string;
    for (char c : target){
        c = tolower(c);
        new_string = new_string + c;
    }
    return new_string;
}

// Helper function that makes sure there is available storage space
bool check_disk_space(const std::string& path, size_t required_space) {
    struct statvfs stat;
    
    // Check the files directory instead of the full path
    if (statvfs("files/", &stat) != 0) {
        return false;
    }
    
    unsigned long long available = stat.f_bavail * stat.f_frsize;
    
    return available >= required_space;
}

// Helper function to get file extension from a filename
std::string get_file_extension(const std::string& filename) {
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos == std::string::npos || dot_pos == filename.length() - 1) {
        return "";  // No extension
    }
    return to_lowercase(filename.substr(dot_pos));
}

// Security check for validating filenames
bool isValidFilename(const std::string& filename) {
    // Checks for empty filenames
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
    
    std::string extension = get_file_extension(filename);
    
    // Ensures there is an extension
    if (extension.empty()) {
        std::cerr << "Security: Must have extension\n";
        return false;
    }
    
    // Check if extension is in allowed list
    bool extension_allowed = false;
    for (const auto& allowed_ext : allowed_extensions) {
        if (extension == to_lowercase(allowed_ext)) {
            extension_allowed = true;
            break;
        }
    }
    
    if (!extension_allowed) {
        std::cerr << "Security: Extension is not allowed\n";
        return false;
    }

    return true;
}

// Helper function to extract and validate filename from path
// All in one func that combines previous few
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

// Overall function to call when the client requests a download
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

    std::cout << "Sent " << filename;

    file.close();

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDownload";
    send(client_socket, response.c_str(), response.length(), 0);
    return;
}

// Handles when the client requests to list all files
// TODO Implement this function
void handleList(int client_socket){
    std::string response = 
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "List";
    send(client_socket, response.c_str(), response.length(), 0);
}

// Overall function to call when client requests a upload
void handleUpload(int client_socket, std::string request){
    std::string boundary;
    size_t boundary_pos = request.find("boundary=");

    if (boundary_pos == std::string::npos){
        std::string response = 
        "HTTP/1.1 400 Bad Request\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "No boundary found";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    size_t boundary_start = boundary_pos + 9;
    size_t boundary_end = request.find("\r\n", boundary_start);

    size_t semicolon_pos = request.find(";", boundary_start);
    if (semicolon_pos != std::string::npos && semicolon_pos < boundary_end){
        boundary_end = semicolon_pos;
    }

    boundary = request.substr(boundary_start, boundary_end - boundary_start);

    boundary = "--" + boundary;

    std::string filename;
    size_t filename_pos = request.find("filename=\"");

    if (filename_pos == std::string::npos){
        std::string response = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "No filename provided";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    size_t filename_start = filename_pos + 10;
    size_t filename_end = request.find("\"", filename_start);
    
    if (filename_end == std::string::npos){
        std::string response = 
        "HTTP/1.1 400 Bad Request\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Invalid filename format";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    filename = request.substr(filename_start, filename_end - filename_start);

    if (filename.empty()){
        std::string response = 
        "HTTP/1.1 400 Bad Request\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "No filename provided";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    size_t header_end = request.find("\r\n\r\n", filename_pos);

    if(header_end ==std::string::npos){
        std::string response = 
        "HTTP/1.1 400 Bad Request\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Malformed multipart data";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    size_t file_data_start = header_end + 4;

    std::string boundary_marker = "\r\n" + boundary;
    size_t file_data_end = request.find(boundary_marker, file_data_start);

    if (file_data_end == std::string::npos){

        file_data_end = request.find(boundary, file_data_start);

        if (file_data_end == std::string::npos){
            std::string response = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Malformed multipart data";
            send(client_socket, response.c_str(), response.length(), 0);
            return;
        }
    }

    std::string file_data = request.substr(file_data_start, file_data_end - file_data_start);

    std::string full_path = "files/" + filename;

    if (!check_disk_space(full_path, file_data.length())){
        std::string response = 
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Not enough storage space";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    std::ofstream outfile(full_path, std::ios::binary);

    if (!outfile.is_open()){
        std::string response = 
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Failed to save file";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }

    outfile.write(file_data.c_str(), file_data.length());
    outfile.close();

    std::cout << "Uploaded file " << filename << "(" << file_data.length() << " bytes)\n";

    std::string response = 
    "HTTP/1.1 200 OK\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "File upload successful";
    send(client_socket, response.c_str(), response.length(), 0);
    return;
}

// Overall function to call when the client requests a delete
// TODO Implement this, make sure it confirms and uses DELETE method
void handleDelete(int client_socket, std::string path){
    std::string response = 
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Delete";
    send(client_socket, response.c_str(), response.length(), 0);
}

// Overall function to call when the client requests the home page
// Returns the home.html file
void handleHome(int client_socket){
    std::string html_content = readHtmlFile("html/home.html");
    
    std::string response = 
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " + std::to_string(html_content.length()) + "\r\n"
        "\r\n" + html_content;
    
    send(client_socket, response.c_str(), response.length(), 0);
}

// Overall function to call when the client requests something, but gets an error
// TODO Implement this into a nice html page
void send404(int client_socket){
    std::string response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "404";
    send(client_socket, response.c_str(), response.length(), 0);
}

// Overall function to call when the client requests a static file, such as an image or css
void handleStaticFile(int client_socket, const std::string& path) {
    // Remove leading slash
    std::string file_path = path.substr(1); // removes the leading "/"
    
    // Security check: prevent directory traversal
    if (file_path.find("..") != std::string::npos) {
        std::cerr << "Security: Directory traversal attempt in static file\n";
        std::string response = "HTTP/1.1 403 Forbidden\r\n\r\nForbidden";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // Check if file exists
    if (!std::filesystem::exists(file_path)) {
        std::cerr << "Static file not found: " << file_path << "\n";
        std::string response = "HTTP/1.1 404 Not Found\r\n\r\nFile not found";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // Read the file
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open static file: " << file_path << "\n";
        std::string response = "HTTP/1.1 500 Internal Server Error\r\n\r\nCannot open file";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    std::size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read file content
    std::vector<char> file_data(file_size);
    file.read(file_data.data(), file_size);
    file.close();
    
    // Determine content type based on file extension
    std::string content_type = "text/plain";
    std::string extension = get_file_extension(file_path);
    
    if (extension == ".css") {
        content_type = "text/css";
    } else if (extension == ".js") {
        content_type = "application/javascript";
    } else if (extension == ".html") {
        content_type = "text/html";
    } else if (extension == ".jpg" || extension == ".jpeg") {
        content_type = "image/jpeg";
    } else if (extension == ".png") {
        content_type = "image/png";
    } else if (extension == ".gif") {
        content_type = "image/gif";
    }
    
    std::string response_headers = 
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(file_size) + "\r\n"
        "\r\n";
    
    // Send headers
    send(client_socket, response_headers.c_str(), response_headers.length(), 0);
    
    // Send file data
    send(client_socket, file_data.data(), file_data.size(), 0);
    
    std::cout << "Served static file: " << file_path << "\n";
}

// Rate limiter, prevents too many attacks per minute from same IP
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

// Makes sure the request is valid
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

// Handles the client, redirects to the relevent function
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
    }else if (req.method == "GET" && req.path.find("/html/static/") == 0) {
        handleStaticFile(client_socket, req.path);
    }
    else if (req.method == "GET" && req.path == "/") {
        handleHome(client_socket);
    }
    else {
        send404(client_socket);
    }
}


// Global flag for server control
std::atomic<bool> server_running(true);

// All the server logic in one func to call
// Uses multi-threading (I think)
void runServer() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (server_fd == -1) {
        std::cerr << "Failed to create socket\n";
        return;
    }
    
    // Allow port reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed\n";
        close(server_fd);
        return;
    }
    
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed\n";
        close(server_fd);
        return;
    }
    
    
    while (server_running) {
        sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        
        // Set timeout so we can check server_running periodically
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        int client_socket = accept(server_fd, (struct sockaddr*)&client_address, &client_len);
        
        if (client_socket < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Timeout, check if we should continue
                continue;
            }
            std::cerr << "Accept failed\n";
            continue;
        }
        
        // Handle the client
        handleClient(client_socket, client_address);
        
        // Close the connection
        close(client_socket);
    }
    
    close(server_fd);
    std::cout << "Server stopped\n";
}

int main() {
    // Create files directory if it doesn't exist
    std::filesystem::create_directories("files");
    
    // Start server in a separate thread
    std::thread serverThread(runServer);
    
    std::cout << "Server started in background thread\n";
    std::cout << "Press Enter to stop the server...\n";
    
    // Wait for user input
    std::cin.get();
    
    // Signal server to stop
    server_running = false;
    
    // Wait for server thread to finish
    std::cout << "Stopping server...\n";
    serverThread.join();
    
    std::cout << "Server stopped successfully\n";
    
    return 0;
}