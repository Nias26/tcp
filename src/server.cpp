#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <future>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <string>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 4096
#define IP_ADDR "192.168.1.2"

std::mutex lock;

void InitializeSSL() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

void DestroySSL() {
  ERR_free_strings();
  EVP_cleanup();
}

void ShutdownSSL(SSL *cSSL) {
  SSL_shutdown(cSSL);
  SSL_free(cSSL);
}

int receive_bytes(int sockfd, SSL *cSSl) {
  int ok;
  char buf[BUF_SIZE]{0};

  memset(buf, 0, sizeof(buf));
  ok = SSL_read(cSSl, buf, sizeof(buf));
  std::cout << "Bytes read: " << ok << std::endl;
  if (ok < 0) {
    std::cerr << "[ERR] SSL_read(): "
              << ERR_error_string(SSL_get_error(cSSl, ok), nullptr)
              << std::endl;
    perror("sys: [ERR] recv(): ");
    return -1;
  }

  if (ok == 0) {
    std::cout << "Client disconnected. Return." << std::endl;
    return 0;
  }

  if (ok > 0) {
    std::string str{buf};
    std::cout << "\nclient]: " << str << std::endl;
  }
  return ok;
}

int send_bytes(int sockfd, SSL *cSSl) {
  int ok;
  std::string line;

  line.erase();
  std::getline(std::cin, line);
  if (line.length() == 0)
    return 0;

  ok = SSL_write(cSSl, line.c_str(), line.size());
  std::cout << "Sent " << ok << " bytes" << std::endl;
  if (ok < 0) {
    std::cerr << "[ERR] SSL_send(): "
              << ERR_error_string(SSL_get_error(cSSl, ok), nullptr)
              << std::endl;
    perror("sys: [ERR] send(): ");
    return -1;
  }
  return ok;
}

std::optional<std::filesystem::path> get_cert(const std::string dirname,
                                              const std::string &filename) {
  using namespace std;
  filesystem::path folder(dirname);
  if (!filesystem::exists(dirname) || !filesystem::is_directory(dirname)) {
    std::cerr << "[ERR] get_cert(): Bad dirname" << std::endl;
    return std::nullopt;
  }

  filesystem::path filepath = folder / filename;
  if (filesystem::exists(filepath) && filesystem::is_regular_file(filepath)) {
    return filepath;
  } else {
    std::cerr << "[ERR] get_cert(): Bad filename" << std::endl;
    return std::nullopt;
  }
}

int main(void) {
  // Initialize SSL envs
  InitializeSSL();
  auto cert = get_cert("./cert", "cert.pem");
  auto key = get_cert("./cert", "key.pem");

  // Create socket and listen for connections
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {AF_INET, htons(8080), {inet_addr(IP_ADDR)}};
  bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  listen(sock, 1);

  // Log
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
  std::cout << "Listening at " << ip_str << " on port " << ntohs(addr.sin_port)
            << std::endl;

  // Create SSL Context
  SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
  SSL_CTX_use_certificate_file(sslctx, cert->c_str(), SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(sslctx, key->c_str(), SSL_FILETYPE_PEM);

  // Get client file descriptor
  int client_fd = accept(sock, nullptr, nullptr);
  SSL *cSSl = SSL_new(sslctx);
  SSL_set_fd(cSSl, client_fd);
  SSL_accept(cSSl);

  const char *ping = "Hello";
  SSL_write(cSSl, ping, strlen(ping));

  struct pollfd fds[2]{{0, POLLIN, 0}, {client_fd, POLLIN, 0}};

  int ok;
  while (true) {
    poll(fds, 2, 5000);

    if (fds[0].revents & POLLIN) {
      ok = send_bytes(sock, cSSl);
      if (ok <= 0)
        break;
    }
    if (fds[1].revents & POLLIN) {
      ok = receive_bytes(sock, cSSl);
      if (ok <= 0)
        break;
    }
  }

  // Deallocate structures and sockets
  DestroySSL();
  ShutdownSSL(cSSl);
  close(client_fd);
  close(sock);
  return 0;
}
