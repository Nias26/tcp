#include <arpa/inet.h>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <print>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#define BUF_SIZE 4096
#define IP_ADDR "192.168.1.2"

static std::mutex lock;

int receive_bytes(std::shared_ptr<int> sockfd) {
  int ok;
  char buf[BUF_SIZE]{0};

  while (true) {
    memset(buf, 0, sizeof(buf));

    ok = recv(*sockfd, buf, sizeof(buf), 0);
    if (*sockfd == -1) {
      std::cerr << "[ERR] recv(): " << strerror(errno) << std::endl;
      close(*sockfd);
      return -1;
    }

    if (ok == 0) {
      std::println("Server disconnected. Return.");
      break;
    }

    std::println("\nserver]: {}", buf);
  }
  return ok;
}

int send_bytes(std::shared_ptr<int> sockfd) {
  int ok;
  std::string line;

  while (true) {
    line.erase();

    std::getline(std::cin, line);
    if (line.length() == 0)
      continue;

    lock.lock();
    int ok = send(*sockfd, line.c_str(), line.size(), 0);
    if (ok == -1) {
      std::cerr << "[ERR] send(): " << strerror(errno) << std::endl;
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
  int ok = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (ok == -1) {
    std::cerr << "[ERR] connect(): " << strerror(errno) << std::endl;
    close(sock);
    return -1;
  }

  std::shared_ptr<int> sh_sock = std::make_shared<int>(sock);

  auto t_send = std::async(std::launch::async, send_bytes, sh_sock);
  auto t_recv = std::async(std::launch::async, receive_bytes, sh_sock);
  t_recv.wait();

  close(sock);
  return 0;
}
