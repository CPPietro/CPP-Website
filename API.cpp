#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <sstream>
#include <arpa/inet.h>

struct HTTPRequest{
    std::string method;
    std::string path;
    std::string version;
};

HTTPRequest parseRequestLine(const std::string* request) {
    HTTPRequest req;
    
    // Get just the first line
    size_t first_line_end = request->find("\r\n");
    std::string first_line = request->substr(0, first_line_end);
    
    // Parse it using string stream
    std::istringstream stream(first_line);
    stream >> req.method >> req.path >> req.version;
    
    return req;
}

void handleDownload(int client_socket, std::string path){
    ;
}

void handleList(int client_socket){
    ;
}

void handleUpload(int client_socket, std::string request){
    ;
}

void handleDelete(int client_socket, std::string path){
    ;
}

void handleHome(int client_socket){
    ;
}

void send404(int client_socket){
    ;
}

void handleClient(int client_socket, sockaddr_in client_address){
    char buffer[1024] = {0};
    read(client_socket, buffer, 1024);
    std::string request(buffer);
    
    HTTPRequest req = parseRequestLine(&request);

    std::cout << "Recieved " << req.method << " " << req.path << " from " << &client_address;

    if (req.method == "GET" && req.path.find("/download/" == 0)){
        handleDownload(client_socket, req.path);
    }else if (req.method == "POST" && req.path == "/upload"){
        handleUpload(client_socket, request);
    }else if (req.method == "GET" && req.path == ("/list")){
        handleList(client_socket);
    }else if (req.method == "DELETE" && req.path.find("/delete") == 0){
        handleDelete(client_socket, req.path);
    }else if (req.method == "GET" && req.path == "/"){
        handleHome(client_socket);
    }else{
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
    std::cout << "Routes:\n";
    std::cout << "  /1 -> returns HELLO\n";
    std::cout << "  /2 -> returns WORLD\n";
    
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