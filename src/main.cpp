#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iostream>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

template <typename T>
auto try_unwrap(std::expected<T, std::string>& result) {
  if constexpr (std::is_void_v<T>) {
    return;
  } else {
    return std::move(*result);
  }
}

#define TRY(expr)                                          \
  ({                                                       \
    auto _result = (expr);                                 \
    if (!_result) return std::unexpected(_result.error()); \
    try_unwrap(_result);                                   \
  })

class BytePacketBuffer {
 public:
  BytePacketBuffer() : m_buf{}, m_pos{} {}

  std::uint8_t* data() { return m_buf.data(); }
  std::size_t size() const { return m_buf.size(); }

  std::size_t pos() const { return m_pos; }
  void step(std::size_t steps) { m_pos += steps; }
  void seek(std::size_t pos) { m_pos = pos; }

  std::expected<std::uint8_t, std::string> read_u8() {
    if (m_pos >= m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }
    std::uint8_t res = m_buf[m_pos];
    m_pos += 1;
    return res;
  }

  std::expected<void, std::string> write_u8(std::uint8_t val) {
    if (m_pos >= 512) {
      return std::unexpected{"End of buffer"};
    }
    m_buf[m_pos] = val;
    m_pos++;
    return {};
  }

  std::expected<std::uint8_t, std::string> get(std::size_t pos) const {
    if (pos >= m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }
    return m_buf[pos];
  }

  std::expected<std::string, std::string> get_range(std::size_t start, std::size_t len) const {
    if (start + len > m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }
    return std::string{m_buf.begin() + start, m_buf.begin() + start + len};
  }

  std::expected<std::uint16_t, std::string> read_u16() {
    std::uint8_t high = TRY(read_u8());
    std::uint8_t low = TRY(read_u8());
    return (static_cast<std::uint16_t>(high) << 8) | low;
  }

  std::expected<void, std::string> write_u16(std::uint16_t val) {
    TRY(write_u8(static_cast<std::uint8_t>(val >> 8)));
    TRY(write_u8(static_cast<std::uint8_t>(val & 0xFF)));
    return {};
  }

  std::expected<std::uint32_t, std::string> read_u32() {
    std::uint8_t b1 = TRY(read_u8());
    std::uint8_t b2 = TRY(read_u8());
    std::uint8_t b3 = TRY(read_u8());
    std::uint8_t b4 = TRY(read_u8());
    return (static_cast<std::uint32_t>(b1) << 24) | (static_cast<std::uint32_t>(b2) << 16) |
           (static_cast<std::uint32_t>(b3) << 8) | b4;
  }

  std::expected<void, std::string> write_u32(std::uint32_t val) {
    TRY(write_u8(static_cast<std::uint8_t>((val >> 24) & 0xFF)));
    TRY(write_u8(static_cast<std::uint8_t>((val >> 16) & 0xFF)));
    TRY(write_u8(static_cast<std::uint8_t>((val >> 8) & 0xFF)));
    TRY(write_u8(static_cast<std::uint8_t>((val >> 0) & 0xFF)));
    return {};
  }

 private:
  std::array<std::uint8_t, 512> m_buf;
  std::size_t m_pos;
};

std::expected<std::string, std::string> read_qname(BytePacketBuffer& buffer) {
  std::string res{};

  std::size_t pos = buffer.pos();

  bool jumped{false};
  int max_jumps{5};
  int jumps_performed{};

  std::string delim = "";

  while (true) {
    if (jumps_performed > max_jumps) {
      return std::unexpected("Limit of " + std::to_string(max_jumps) + "jumps exceeded");
    }

    std::uint8_t len = TRY(buffer.get(pos));

    if ((len & 0xC0) == 0xC0) {
      if (!jumped) {
        buffer.seek(pos + 2);
      }

      std::uint16_t b2 = TRY(buffer.get(pos + 1));
      std::uint16_t offset = ((static_cast<std::uint16_t>(len) ^ 0xC0) << 8) | b2;
      pos = offset;

      jumped = true;
      jumps_performed++;

      continue;
    } else {
      pos++;

      if (len == 0) {
        break;
      }

      res += delim;

      std::string str_buffer = TRY(buffer.get_range(pos, len));
      std::transform(str_buffer.begin(), str_buffer.end(), str_buffer.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      res += str_buffer;

      delim = ".";

      pos += len;
    }
  }

  if (!jumped) {
    buffer.seek(pos);
  }

  return res;
}

std::expected<void, std::string> write_qname(BytePacketBuffer& buffer, const std::string& qname) {
  for (auto const label : qname | std::views::split('.')) {
    auto len = label.size();
    if (len > 0x3f) {
      return std::unexpected<std::string>{"Single label exceeds 63 characters of length"};
    }
    TRY(buffer.write_u8(static_cast<std::uint8_t>(len)));
    for (auto const c : label) {
      TRY(buffer.write_u8(static_cast<std::uint8_t>(c)));
    }
  }
  TRY(buffer.write_u8(0));
  return {};
}

enum class QueryType : std::uint16_t {
  UNKNOWN,
  A = 1,
};

std::uint16_t to_num(QueryType type) {
  switch (type) {
    case QueryType::A:
      return 1;
    default:
      return 0;
  }
}

QueryType query_type_from_num(std::uint16_t num) {
  switch (num) {
    case 1:
      return QueryType::A;
    default:
      return QueryType::UNKNOWN;
  }
}

std::string_view to_string(QueryType type) {
  switch (type) {
    case QueryType::A:
      return "A";
    default:
      return "UNKNOWN";
  }
}

enum class ResultCode : std::uint8_t {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5,
};

ResultCode result_code_from_num(std::uint8_t num) {
  switch (num) {
    case 1:
      return ResultCode::FORMERR;
    case 2:
      return ResultCode::SERVFAIL;
    case 3:
      return ResultCode::NXDOMAIN;
    case 4:
      return ResultCode::NOTIMP;
    case 5:
      return ResultCode::REFUSED;
    default:
      return ResultCode::NOERROR;
  }
}

std::string_view to_string(ResultCode code) {
  switch (code) {
    case ResultCode::NOERROR:
      return "NOERROR";
    case ResultCode::FORMERR:
      return "FORMERR";
    case ResultCode::SERVFAIL:
      return "SERVFAIL";
    case ResultCode::NXDOMAIN:
      return "NXDOMAIN";
    case ResultCode::NOTIMP:
      return "NOTIMP";
    case ResultCode::REFUSED:
      return "REFUSED";
    default:
      return "UNKNOWN";
  }
}

struct DnsHeader {
  std::uint16_t id;

  bool recursion_desired;
  bool truncated_message;
  bool authoritative_answer;
  std::uint8_t opcode;
  bool response;

  ResultCode rescode;
  bool checking_disabled;
  bool authed_data;
  bool z;
  bool recursion_available;

  std::uint16_t questions;
  std::uint16_t answers;
  std::uint16_t authoritative_entries;
  std::uint16_t resource_entries;
};

std::ostream& operator<<(std::ostream& os, const DnsHeader& h) {
  os << "DnsHeader {\n"
     << "    id: " << h.id << ",\n"
     << "    recursion_desired: " << (h.recursion_desired ? "true" : "false") << ",\n"
     << "    truncated_message: " << (h.truncated_message ? "true" : "false") << ",\n"
     << "    authoritative_answer: " << (h.authoritative_answer ? "true" : "false") << ",\n"
     << "    opcode: " << (int)h.opcode << ",\n"
     << "    response: " << (h.response ? "true" : "false") << ",\n"
     << "    rescode: " << to_string(h.rescode) << ",\n"
     << "    checking_disabled: " << (h.checking_disabled ? "true" : "false") << ",\n"
     << "    authed_data: " << (h.authed_data ? "true" : "false") << ",\n"
     << "    z: " << (h.z ? "true" : "false") << ",\n"
     << "    recursion_available: " << (h.recursion_available ? "true" : "false") << ",\n"
     << "    questions: " << h.questions << ",\n"
     << "    answers: " << h.answers << ",\n"
     << "    authoritative_entries: " << h.authoritative_entries << ",\n"
     << "    resource_entries: " << h.resource_entries << "\n"
     << "}";
  return os;
}

struct DnsQuestion {
  std::string name;
  QueryType qtype;
};

std::ostream& operator<<(std::ostream& os, const DnsQuestion& q) {
  os << "DnsQuestion {\n"
     << "    name: \"" << q.name << "\",\n"
     << "    qtype: " << to_string(q.qtype) << "\n"
     << "}";
  return os;
}

struct Ipv4Addr {
  std::uint8_t a, b, c, d;

  std::string to_string() const {
    return std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
  }
};

class DnsRecord {
 public:
  virtual ~DnsRecord() = default;

  virtual const std::string& domain() const = 0;
  virtual std::uint32_t ttl() const = 0;

  virtual void print(std::ostream& os) const = 0;
  friend std::ostream& operator<<(std::ostream& os, const DnsRecord& r) {
    r.print(os);
    return os;
  }
  static std::expected<std::unique_ptr<DnsRecord>, std::string> read(BytePacketBuffer& buffer);
  virtual std::expected<std::size_t, std::string> write(BytePacketBuffer& buffer) const = 0;
};

class ARecord : public DnsRecord {
 private:
  std::string m_domain;
  Ipv4Addr m_addr;
  std::uint32_t m_ttl;

 public:
  ARecord(std::string domain, Ipv4Addr addr, std::uint32_t ttl) : m_domain{domain}, m_addr{addr}, m_ttl{ttl} {};

  const std::string& domain() const override { return m_domain; }
  std::uint32_t ttl() const override { return m_ttl; }
  const Ipv4Addr& addr() const { return m_addr; }

  void print(std::ostream& os) const override {
    os << "A {\n"
       << "    domain: \"" << m_domain << "\",\n"
       << "    addr: " << m_addr.to_string() << ",\n"
       << "    ttl: " << m_ttl << "\n"
       << "}";
  };

  std::expected<std::size_t, std::string> write(BytePacketBuffer& buffer) const override {
    auto start_pos = buffer.pos();

    TRY(write_qname(buffer, m_domain));
    TRY(buffer.write_u16(to_num(QueryType::A)));
    TRY(buffer.write_u16(1));  // CLASS: IN = 1
    TRY(buffer.write_u32(m_ttl));
    TRY(buffer.write_u16(4));

    TRY(buffer.write_u8(m_addr.a));
    TRY(buffer.write_u8(m_addr.b));
    TRY(buffer.write_u8(m_addr.c));
    TRY(buffer.write_u8(m_addr.d));

    return {buffer.pos() - start_pos};
  }
};

class UnknownRecord : public DnsRecord {
 private:
  std::string m_domain;
  std::uint16_t m_qtype;
  std::uint16_t m_data_len;
  std::uint32_t m_ttl;

 public:
  UnknownRecord(std::string domain, std::uint16_t qtype, std::uint16_t data_len, std::uint32_t ttl)
      : m_domain{domain}, m_qtype{qtype}, m_data_len{data_len}, m_ttl{ttl} {}

  const std::string& domain() const override { return m_domain; }
  std::uint32_t ttl() const override { return m_ttl; }
  std::uint16_t qtype() const { return m_qtype; }
  std::uint16_t data_len() const { return m_data_len; }

  void print(std::ostream& os) const override {
    os << "Unknown {\n"
       << "    domain: \"" << m_domain << "\",\n"
       << "    type: " << m_qtype << ",\n"
       << "    len: " << m_data_len << ",\n"
       << "    ttl: " << m_ttl << "\n"
       << "}";
  }

  std::expected<std::size_t, std::string> write(BytePacketBuffer& /*buffer*/) const override { return {0}; }
};

struct DnsPacket {
  DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<std::unique_ptr<DnsRecord>> answers;
  std::vector<std::unique_ptr<DnsRecord>> authorities;
  std::vector<std::unique_ptr<DnsRecord>> resources;
};

std::expected<DnsHeader, std::string> read_dns_header(BytePacketBuffer& buffer) {
  DnsHeader h{};

  h.id = TRY(buffer.read_u16());

  std::uint16_t flags = TRY(buffer.read_u16());
  std::uint8_t a = (flags >> 8);
  std::uint8_t b = (flags & 0xFF);
  h.recursion_desired = (a & (1 << 0)) > 0;
  h.truncated_message = (a & (1 << 1)) > 0;
  h.authoritative_answer = (a & (1 << 2)) > 0;
  h.opcode = (a >> 3) & 0x0F;
  h.response = (a & (1 << 7)) > 0;

  h.rescode = result_code_from_num(b & 0x0F);
  h.checking_disabled = (b & (1 << 4)) > 0;
  h.authed_data = (b & (1 << 5)) > 0;
  h.z = (b & (1 << 6)) > 0;
  h.recursion_available = (b & (1 << 7)) > 0;

  h.questions = TRY(buffer.read_u16());
  h.answers = TRY(buffer.read_u16());
  h.authoritative_entries = TRY(buffer.read_u16());
  h.resource_entries = TRY(buffer.read_u16());

  return h;
}

std::expected<void, std::string> write_dns_header(BytePacketBuffer& buffer, const DnsHeader& header) {
  TRY(buffer.write_u16(header.id));

  TRY(buffer.write_u8(
      static_cast<std::uint8_t>(header.recursion_desired) | (static_cast<std::uint8_t>(header.truncated_message) << 1) |
      (static_cast<std::uint8_t>(header.authoritative_answer) << 2) | (static_cast<std::uint8_t>(header.opcode) << 3) |
      (static_cast<std::uint8_t>(header.response) << 7)));

  TRY(buffer.write_u8(
      static_cast<std::uint8_t>(header.rescode) | (static_cast<std::uint8_t>(header.checking_disabled) << 4) |
      (static_cast<std::uint8_t>(header.authed_data) << 5) | (static_cast<std::uint8_t>(header.z) << 6) |
      (static_cast<std::uint8_t>(header.recursion_desired) << 7)));

  TRY(buffer.write_u16(header.questions));
  TRY(buffer.write_u16(header.answers));
  TRY(buffer.write_u16(header.authoritative_entries));
  TRY(buffer.write_u16(header.resource_entries));
  return {};
}

std::expected<DnsQuestion, std::string> read_dns_question(BytePacketBuffer& buffer) {
  DnsQuestion q{};
  q.name = TRY(read_qname(buffer));
  q.qtype = query_type_from_num(TRY(buffer.read_u16()));
  TRY(buffer.read_u16());  // skip class
  return q;
}

std::expected<void, std::string> write_dns_question(BytePacketBuffer& buffer, const DnsQuestion& question) {
  TRY(write_qname(buffer, question.name));

  uint16_t typenum = to_num(question.qtype);
  TRY(buffer.write_u16(typenum));
  TRY(buffer.write_u16(1));
  return {};
}

std::expected<std::unique_ptr<DnsRecord>, std::string> DnsRecord::read(BytePacketBuffer& buffer) {
  std::string domain = TRY(read_qname(buffer));

  std::uint16_t qtype_num = TRY(buffer.read_u16());
  QueryType qtype = query_type_from_num(qtype_num);
  TRY(buffer.read_u16());  // skip class
  std::uint32_t ttl = TRY(buffer.read_u32());
  std::uint16_t data_len = TRY(buffer.read_u16());

  switch (qtype) {
    case QueryType::A: {
      std::uint32_t raw_addr = TRY(buffer.read_u32());
      Ipv4Addr addr{
          static_cast<std::uint8_t>((raw_addr >> 24) & 0xFF),
          static_cast<std::uint8_t>((raw_addr >> 16) & 0xFF),
          static_cast<std::uint8_t>((raw_addr >> 8) & 0xFF),
          static_cast<std::uint8_t>((raw_addr >> 0) & 0xFF),
      };
      return std::make_unique<ARecord>(std::move(domain), addr, ttl);
    }
    default: {
      buffer.step(data_len);
      return std::make_unique<UnknownRecord>(std::move(domain), qtype_num, data_len, ttl);
    }
  }
}

std::expected<DnsPacket, std::string> read_dns_packet(BytePacketBuffer& buffer) {
  DnsPacket packet{};

  packet.header = TRY(read_dns_header(buffer));

  for (int i = 0; i < packet.header.questions; i++) {
    packet.questions.push_back(TRY(read_dns_question(buffer)));
  }

  for (int i = 0; i < packet.header.answers; i++) {
    packet.answers.emplace_back(TRY(DnsRecord::read(buffer)));
  }

  for (int i = 0; i < packet.header.authoritative_entries; i++) {
    packet.authorities.emplace_back(TRY(DnsRecord::read(buffer)));
  }

  for (int i = 0; i < packet.header.resource_entries; i++) {
    packet.resources.emplace_back(TRY(DnsRecord::read(buffer)));
  }

  return packet;
}

std::expected<void, std::string> write_dns_packet(BytePacketBuffer& buffer, DnsPacket& packet) {
  packet.header.questions = packet.questions.size();
  packet.header.answers = packet.answers.size();
  packet.header.authoritative_entries = packet.authorities.size();
  packet.header.resource_entries = packet.resources.size();

  TRY(write_dns_header(buffer, packet.header));

  for (const auto& question : packet.questions) {
    TRY(write_dns_question(buffer, question));
  }

  for (const auto& rec : packet.answers) {
    TRY(rec->write(buffer));
  }

  for (const auto& rec : packet.authorities) {
    TRY(rec->write(buffer));
  }

  for (const auto& rec : packet.resources) {
    TRY(rec->write(buffer));
  }

  return {};
}

int main() {
  std::string qname{"baidu.com"};
  QueryType qtype{QueryType::A};

  std::string server_ip{"8.8.8.8"};
  std::uint16_t port{53};

  DnsPacket packet{};
  packet.header.id = 6666;
  packet.header.questions = 1;
  packet.header.recursion_desired = true;
  packet.questions.emplace_back(qname, qtype);

  BytePacketBuffer req_buffer{};
  auto write_result = write_dns_packet(req_buffer, packet);
  if (!write_result) {
    std::cerr << write_result.error();
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

  sendto(sock, req_buffer.data(), req_buffer.pos(), 0, (struct sockaddr*)&addr, sizeof(addr));

  struct sockaddr_in src_addr{};
  socklen_t src_len = sizeof(src_addr);
  BytePacketBuffer res_buffer{};
  recvfrom(sock, res_buffer.data(), res_buffer.size(), 0, (struct sockaddr*)&src_addr, &src_len);
  res_buffer.seek(0);

  auto packet_result = read_dns_packet(res_buffer);
  if (!packet_result) {
    std::cerr << packet_result.error();
    return 1;
  }

  const auto& res = *packet_result;
  std::cout << res.header << "\n";
  for (const auto& q : res.questions) std::cout << q << "\n";
  for (const auto& r : res.answers) std::cout << *r << "\n";
  for (const auto& r : res.authorities) std::cout << *r << "\n";
  for (const auto& r : res.resources) std::cout << *r << "\n";

  return 0;
}
