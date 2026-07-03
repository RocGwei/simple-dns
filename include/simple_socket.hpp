#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <netinet/in.h>
#include <unistd.h>

class SocketAddr {
 public:
  enum class Family {
    IPv4 = AF_INET,
    IPv6 = AF_INET6,
  };

  Family family() const { return m_family; }

  static std::expected<SocketAddr, std::error_code> ipv4(const std::string& ip, std::uint16_t port);
  static std::expected<SocketAddr, std::error_code> ipv6(const std::string& ip, std::uint16_t port);
  static std::expected<SocketAddr, std::error_code> parse(Family family, const std::string& ip, std::uint16_t port);

  sockaddr_storage to_sockaddr() const;
  static SocketAddr from_sockaddr(const sockaddr* addr);

 private:
  Family m_family;
  std::string m_ip;
  std::uint16_t m_port;

  union {
    in_addr v4;
    in6_addr v6;
  } m_addr;

  SocketAddr(Family f, std::string ip, const void* addr, uint16_t port)
      : m_family{f},
        m_ip{std::move(ip)},
        m_port{port} {
    if (f == Family::IPv4) {
      this->m_addr.v4 = *static_cast<const in_addr*>(addr);
    } else {
      this->m_addr.v6 = *static_cast<const in6_addr*>(addr);
    }
  }
};

class UdpSocket {
 public:
  static std::expected<UdpSocket, std::error_code> bind(SocketAddr addr);
  std::expected<std::pair<std::size_t, SocketAddr>, std::error_code> recv_from(std::span<std::uint8_t> buffer);
  std::expected<std::size_t, std::error_code> send_to(std::span<const std::uint8_t> data, const SocketAddr& dest);
  std::expected<SocketAddr, std::error_code> peer_addr() const;
  std::expected<SocketAddr, std::error_code> local_addr() const;

  // 禁用拷贝
  UdpSocket(const UdpSocket&) = delete;

  // 移动时避免源sock关闭
  UdpSocket(UdpSocket&& other) noexcept
      : m_sock(other.m_sock) {
    other.m_sock = -1;
  };

  // 移动复制运算符
  UdpSocket& operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
      if (m_sock >= 0) close(m_sock);
      m_sock = other.m_sock;
      other.m_sock = -1;
    }
    return *this;
  };
  ~UdpSocket() {
    if (m_sock >= 0) close(m_sock);
  }

 private:
  explicit UdpSocket(int sock)
      : m_sock{sock} {};
  int m_sock;
};
