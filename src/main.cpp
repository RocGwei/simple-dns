#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fstream>
#include <iostream>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

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

  // Current position within buffer
  std::size_t pos() const { return m_pos; }

  // Step the buffer position forward a specific number of steps
  void step(std::size_t steps) { m_pos += steps; }

  // Change the buffer position
  void seek(std::size_t pos) { m_pos = pos; }

  // Read a single byte and move the position one step forward
  std::expected<std::uint8_t, std::string> read() {
    if (m_pos >= m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }

    std::uint8_t res = m_buf[m_pos];
    m_pos += 1;

    return res;
  }

  // Get a single byte, without changing the buffer position
  std::expected<std::uint8_t, std::string> get(std::size_t pos) const {
    if (pos >= m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }

    return m_buf[pos];
  }

  // Get a range of bytes
  std::expected<std::string, std::string> get_range(std::size_t start, std::size_t len) const {
    if (start + len >= m_buf.size()) {
      return std::unexpected<std::string>{"End of buffer"};
    }

    return std::string{m_buf.begin() + start, m_buf.begin() + start + len};
  }

  // Read two bytes, stepping two steps forward
  std::expected<std::uint16_t, std::string> read_u16() {
    auto high = read();
    if (!high) return std::unexpected(high.error());
    auto low = read();
    if (!low) return std::unexpected(low.error());
    return (static_cast<std::uint16_t>(*high) << 8) | *low;
  }

  // Read four bytes, stepping four steps forward
  std::expected<std::uint32_t, std::string> read_u32() {
    auto b1 = read();
    if (!b1) return std::unexpected(b1.error());
    auto b2 = read();
    if (!b2) return std::unexpected(b2.error());
    auto b3 = read();
    if (!b3) return std::unexpected(b3.error());
    auto b4 = read();
    if (!b4) return std::unexpected(b4.error());
    return (static_cast<std::uint32_t>(*b1) << 24) | (static_cast<std::uint32_t>(*b2) << 16) |
           (static_cast<std::uint32_t>(*b3) << 8) | *b4;
  }

  /**
   * Read a qname
   *
   * The tricky part: Reading domain names, taking labels into consideration.
   * Will take something like [3]www[6]google[3]com[0] and return
   * www.google.com.
   */
  std::expected<std::string, std::string> read_qname() {
    std::string res{};

    // Since we might encounter jumps, we'll keep track of our position
    // locally as opposed to using the position within the struct. This
    // allows us to move the shared position to a point past our current
    // qname, while keeping track of our progress on the current qname
    // using this variable.
    std::size_t pos = this->pos();

    // track whether or not we've jumped
    bool jumped{false};
    int max_jumps{5};
    int jumps_performed{};

    // Our delimiter which we append for each label. Since we don't want a
    // dot at the beginning of the domain name we'll leave it empty for now
    // and set it to "." at the end of the first iteration.
    std::string delim = "";

    while (true) {
      if (jumps_performed > max_jumps) {
        return std::unexpected("Limit of " + std::to_string(max_jumps) + "jumps exceeded");
      }

      // At this point, we're always at the beginning of a label. Recall
      // that labels start with a length byte.
      std::uint8_t len = TRY(get(pos));

      // If len has the two most significant bit are set, it represents a
      // jump to some other offset in the packet:
      if ((len & 0xC0) == 0xC0) {
        // Update the buffer position to a point past the current
        // label. We don't need to touch it any further.
        if (!jumped) {
          seek(pos + 2);
        }

        // Read another byte, calculate offset and perform the jump by
        // updating our local position variable
        std::uint16_t b2 = TRY(get(pos + 1));
        std::uint16_t offset = ((static_cast<std::uint16_t>(len) ^ 0xC0) << 8) | b2;
        pos = offset;

        // Indicate that a jump was performed.
        jumped = true;
        jumps_performed++;

        continue;
      }
      // The base scenario, where we're reading a single label and
      // appending it to the output:
      else {
        // Move a single byte forward to move past the length byte.
        pos++;

        // Domain names are terminated by an empty label of length 0,
        // so if the length is zero we're done.
        if (len == 0) {
          break;
        }

        // Append the delimiter to our output buffer first.
        res += delim;

        // Extract the actual ASCII bytes for this label and append them
        // to the output buffer.
        std::string str_buffer = TRY(get_range(pos, len));
        std::transform(str_buffer.begin(), str_buffer.end(), str_buffer.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        res += str_buffer;

        delim = ".";

        // Move forward the full length of the label.
        pos += len;
      }
    }

    if (!jumped) {
      seek(pos);
    }

    return res;
  }

 private:
  std::array<std::uint8_t, 512> m_buf;
  std::size_t m_pos;
};

struct DnsHeader {
  enum class ResultCode : std::uint8_t {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
  };

  static ResultCode from_num(std::uint8_t num) {
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

  static std::string_view to_string(ResultCode rc) {
    switch (rc) {
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

  std::expected<void, std::string> read(BytePacketBuffer& buffer) {
    id = TRY(buffer.read_u16());

    std::uint16_t flags = TRY(buffer.read_u16());
    std::uint8_t a = (flags >> 8);
    std::uint8_t b = (flags & 0xFF);
    recursion_desired = (a & (1 << 0)) > 0;
    truncated_message = (a & (1 << 1)) > 0;
    authoritative_answer = (a & (1 << 2)) > 0;
    opcode = (a >> 3) & 0x0F;
    response = (a & (1 << 7)) > 0;

    rescode = from_num(b & 0x0F);
    checking_disabled = (b & (1 << 4)) > 0;
    authed_data = (b & (1 << 5)) > 0;
    z = (b & (1 << 6)) > 0;
    recursion_available = (b & (1 << 7)) > 0;

    questions = TRY(buffer.read_u16());
    answers = TRY(buffer.read_u16());
    authoritative_entries = TRY(buffer.read_u16());
    resource_entries = TRY(buffer.read_u16());

    return {};
  }

  friend std::ostream& operator<<(std::ostream& os, const DnsHeader& h) {
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
};

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

QueryType from_num(std::uint16_t num) {
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

struct DnsQuestion {
  std::string name;
  QueryType qtype;

  std::expected<void, std::string> read(BytePacketBuffer& buffer) {
    name = TRY(buffer.read_qname());
    qtype = from_num(TRY(buffer.read_u16()));
    TRY(buffer.read_u16());  // skip class
    return {};
  }

  friend std::ostream& operator<<(std::ostream& os, const DnsQuestion& q) {
    os << "DnsQuestion {\n"
       << "    name: \"" << q.name << "\",\n"
       << "    qtype: " << to_string(q.qtype) << "\n"
       << "}";
    return os;
  }
};

struct Ipv4Addr {
  std::uint8_t a, b, c, d;

  std::string to_string() const {
    return std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
  }
};

struct ARecord {
  std::string domain;
  Ipv4Addr addr;
  std::uint32_t ttl;

  friend std::ostream& operator<<(std::ostream& os, const ARecord& r) {
    os << "A {\n"
       << "    domain: \"" << r.domain << "\",\n"
       << "    addr: " << r.addr.to_string() << ",\n"
       << "    ttl: " << r.ttl << "\n"
       << "}";
    return os;
  }
};

struct UnknownRecord {
  std::string domain;
  std::uint16_t qtype;
  std::uint16_t data_len;
  std::uint32_t ttl;

  friend std::ostream& operator<<(std::ostream& os, const UnknownRecord& r) {
    os << "Unknown {\n"
       << "    domain: \"" << r.domain << "\",\n"
       << "    type: " << r.qtype << ",\n"
       << "    len: " << r.data_len << ",\n"
       << "    ttl: " << r.ttl << "\n"
       << "}";
    return os;
  }
};

using DnsRecord = std::variant<ARecord, UnknownRecord>;

std::expected<DnsRecord, std::string> read_dns_record(BytePacketBuffer& buffer) {
  std::string domain = TRY(buffer.read_qname());

  std::uint16_t qtype_num = TRY(buffer.read_u16());
  QueryType qtype = from_num(qtype_num);
  TRY(buffer.read_u16());  // 跳过 class（忽略）
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
      return ARecord{std::move(domain), addr, ttl};
    }
    default: {
      buffer.step(data_len);
      return UnknownRecord{std::move(domain), qtype_num, data_len, ttl};
    }
  }
}

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;
struct DnsPacket {
  DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<DnsRecord> answers;
  std::vector<DnsRecord> authorities;
  std::vector<DnsRecord> resources;

  std::expected<void, std::string> from_buffer(BytePacketBuffer& buffer) {
    TRY(header.read(buffer));

    for (int i = 0; i < header.questions; i++) {
      DnsQuestion question{};
      TRY(question.read(buffer));
      questions.push_back(question);
    }

    for (int i = 0; i < header.answers; i++) {
      answers.emplace_back(TRY(read_dns_record(buffer)));
    }

    for (int i = 0; i < header.authoritative_entries; i++) {
      authorities.emplace_back(TRY(read_dns_record(buffer)));
    }

    for (int i = 0; i < header.resource_entries; i++) {
      resources.emplace_back(TRY(read_dns_record(buffer)));
    }
    return {};
  }
};

int main() {
  std::ifstream file("response_packet.txt", std::ios::binary);
  if (!file) {
    std::cerr << "Failed to open response_packet.txt" << std::endl;
    return 1;
  }

  BytePacketBuffer buffer;
  file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

  // 检查实际读取了多少字节（可选）
  std::streamsize bytes_read = file.gcount();
  std::cout << "Read " << bytes_read << " bytes from file" << std::endl;

  DnsPacket packet;
  auto result = packet.from_buffer(buffer);
  if (!result) {
    std::cerr << result.error();
  }

  std::cout << "\n=== Header ===" << std::endl;
  std::cout << packet.header << std::endl;

  std::cout << "\n=== Questions (" << packet.questions.size() << ") ===" << std::endl;
  for (const auto& q : packet.questions) {
    std::cout << "  " << q << std::endl;
  }

  auto print_records = [](const std::string& label, const std::vector<DnsRecord>& records) {
    std::cout << "\n=== " << label << " (" << records.size() << ") ===" << std::endl;
    for (const auto& rec : records) {
      std::visit([](const auto& r) { std::cout << r << std::endl; }, rec);
    }
  };

  print_records("Answers", packet.answers);
  print_records("Authorities", packet.authorities);
  print_records("Resources", packet.resources);

  return 0;
}
