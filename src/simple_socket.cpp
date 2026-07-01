#include "simple_socket.hpp"

#include <arpa/inet.h>

std::expected<SocketAddr, std::error_code> SocketAddr::ipv4(const std::string& ip, std::uint16_t port) {
  return parse(Family::IPv4, ip, port);
}

std::expected<SocketAddr, std::error_code> SocketAddr::ipv6(const std::string& ip, std::uint16_t port) {
  return parse(Family::IPv6, ip, port);
}

std::expected<SocketAddr, std::error_code> SocketAddr::parse(Family family, const std::string& ip, std::uint16_t port) {
  union {
    in_addr v4;
    in6_addr v6;
  } addr;

  if (inet_pton(static_cast<int>(family), ip.c_str(), &addr) <= 0) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  char canonical[INET6_ADDRSTRLEN];
  if (inet_ntop(static_cast<int>(family), &addr, canonical, sizeof(canonical)) == nullptr) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }

  return SocketAddr(family, std::string(canonical), &addr, port);
}

sockaddr_storage SocketAddr::to_sockaddr() const {
  sockaddr_storage storage{};
  if (m_family == Family::IPv4) {
    auto* in = reinterpret_cast<struct sockaddr_in*>(&storage);
    in->sin_family = AF_INET;
    in->sin_port = htons(m_port);
    in->sin_addr = m_addr.v4;
  } else {
    auto* in6 = reinterpret_cast<struct sockaddr_in6*>(&storage);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(m_port);
    in6->sin6_addr = m_addr.v6;
  }
  return storage;
}

SocketAddr SocketAddr::from_sockaddr(const sockaddr* addr) {
  if (addr->sa_family == AF_INET) {
    auto* in = reinterpret_cast<const struct sockaddr_in*>(addr);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf));
    return {Family::IPv4, buf, &in->sin_addr, ntohs(in->sin_port)};
  } else {
    auto* in6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf));
    return {Family::IPv6, buf, &in6->sin6_addr, ntohs(in6->sin6_port)};
  }
}

std::expected<UdpSocket, std::error_code> UdpSocket::bind(SocketAddr addr) {
  int sock = socket(static_cast<int>(addr.family()), SOCK_DGRAM, 0);
  if (sock < 0) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }

  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
    close(sock);
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }

  sockaddr_storage storage = addr.to_sockaddr();
  socklen_t len = (addr.family() == SocketAddr::Family::IPv4)
                      ? sizeof(sockaddr_in)
                      : sizeof(sockaddr_in6);
  if (::bind(sock, reinterpret_cast<struct sockaddr*>(&storage), len) != 0) {
    close(sock);
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }

  return UdpSocket(sock);
}

std::expected<std::pair<std::size_t, SocketAddr>, std::error_code> UdpSocket::recv_from(std::span<std::uint8_t> buffer) {
  sockaddr_storage src_addr;
  socklen_t addr_len = sizeof(src_addr);
  ssize_t n = recvfrom(m_sock, buffer.data(), buffer.size(), 0,
                       reinterpret_cast<struct sockaddr*>(&src_addr), &addr_len);
  if (n < 0) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }
  SocketAddr addr = SocketAddr::from_sockaddr(
      reinterpret_cast<struct sockaddr*>(&src_addr));
  return std::pair{static_cast<size_t>(n), std::move(addr)};
}

std::expected<std::size_t, std::error_code> UdpSocket::send_to(std::span<const std::uint8_t> data, const SocketAddr& dest) {
  sockaddr_storage storage = dest.to_sockaddr();
  socklen_t len = (dest.family() == SocketAddr::Family::IPv4)
                      ? sizeof(sockaddr_in)
                      : sizeof(sockaddr_in6);
  ssize_t n = sendto(m_sock, data.data(), data.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&storage), len);
  if (n < 0) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }
  return static_cast<std::size_t>(n);
}

std::expected<SocketAddr, std::error_code> UdpSocket::peer_addr() const {
  sockaddr_storage addr;
  socklen_t len = sizeof(addr);
  if (getpeername(m_sock, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }
  return SocketAddr::from_sockaddr(reinterpret_cast<struct sockaddr*>(&addr));
}

std::expected<SocketAddr, std::error_code> UdpSocket::local_addr() const {
  sockaddr_storage addr;
  socklen_t len = sizeof(addr);
  if (getsockname(m_sock, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
    return std::unexpected(std::error_code{errno, std::generic_category()});
  }
  return SocketAddr::from_sockaddr(reinterpret_cast<struct sockaddr*>(&addr));
}
