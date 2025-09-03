/*
 * TODO: Add OpenSSL Security Layer to encrypt connection
 */

#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 4096
#define IP_ADDR "192.168.1.2"

std::mutex lock;

int receive_bytes(std::shared_ptr<int> sockfd, std::shared_ptr<int> clientfd) {
  int ok;
  char buf[BUF_SIZE]{0};

  while (true) {
    memset(buf, 0, sizeof(buf));

    ok = recv(*clientfd, buf, sizeof(buf), 0);

    if (*sockfd == -1) {
      std::cerr << "[ERR] recv(): " << strerror(errno) << std::endl;
      close(*clientfd);
      close(*sockfd);
      return -1;
    }

    if (ok == 0) {
      std::cout << "Client disconnecter. Return." << std::endl;
      break;
    }

    std::cout << "\nclient]: " << buf << std::endl;
  }
  return ok;
}

int send_bytes(std::shared_ptr<int> sockfd, std::shared_ptr<int> clientfd) {
  int ok;
  std::string line;

  while (true) {
    line.erase();

    std::getline(std::cin, line);
    if (line.length() == 0)
      continue;

    lock.lock();
    int ok = send(*clientfd, line.c_str(), line.size(), 0);
    if (ok == -1) {
      std::cerr << "[ERR] send(): " << strerror(errno) << std::endl;
      close(*clientfd);
      close(*sockfd);
      return -1;
    }
    lock.unlock();
  }
  return ok;
}

int main(void) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {AF_INET, htons(8080), {inet_addr(IP_ADDR)}};
  int ok = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (ok == -1) {
    std::cerr << "[ERR] bind(): " << strerror(errno) << std::endl;
    close(sock);
    return -1;
  }

  ok = listen(sock, 1);
  if (ok == -1) {
    std::cerr << "[ERR] listen(): " << strerror(errno) << std::endl;
    close(sock);
    return -1;
  }

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

  std::cout << "Listening at " << ip_str << " on port " << ntohs(addr.sin_port);

  int client_fd = accept(sock, NULL, NULL);
  if (client_fd == -1) {
    std::cerr << "[ERR] accept(): " << strerror(errno) << std::endl;
    close(sock);
    return -1;
  }

  std::shared_ptr<int> sh_sock = std::make_shared<int>(sock);
  std::shared_ptr<int> sh_client_fd = std::make_shared<int>(client_fd);

  auto t_recv =
      std::async(std::launch::async, receive_bytes, sh_sock, sh_client_fd);
  auto t_send =
      std::async(std::launch::async, send_bytes, sh_sock, sh_client_fd);
  t_recv.wait();

  close(client_fd);
  close(sock);
  return 0;
}
