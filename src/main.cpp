#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

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
  std::uint8_t read() {
    check_bounds(m_pos);

    std::uint8_t res = m_buf[m_pos];
    m_pos += 1;

    return res;
  }

  // Get a single byte, without changing the buffer position
  std::uint8_t get(std::size_t pos) const {
    check_bounds(pos);

    return m_buf[pos];
  }

  // Get a range of bytes
  std::string get_range(std::size_t start, std::size_t len) const {
    check_bounds(start + len);

    return {m_buf.begin() + start, m_buf.begin() + start + len};
  }

  // Read two bytes, stepping two steps forward
  std::uint16_t read_u16() {
    std::uint16_t res = (static_cast<std::uint16_t>(read()) << 8) | (static_cast<std::uint16_t>(read()));
    return res;
  }

  // Read four bytes, stepping four steps forward
  std::uint32_t read_u32() {
    std::uint32_t res = (static_cast<std::uint32_t>(read()) << 24) | (static_cast<std::uint32_t>(read()) << 16) |
                        (static_cast<std::uint32_t>(read()) << 8) | (static_cast<std::uint32_t>(read()) << 0);
    return res;
  }

  /**
   * Read a qname
   *
   * The tricky part: Reading domain names, taking labels into consideration.
   * Will take something like [3]www[6]google[3]com[0] and return
   * www.google.com.
   */
  std::string read_qname() {
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
        throw std::runtime_error("Limit of " + std::to_string(max_jumps) + "jumps exceeded");
      }

      // At this point, we're always at the beginning of a label. Recall
      // that labels start with a length byte.
      std::uint8_t len = get(pos);

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
        std::uint16_t b2 = get(pos + 1);
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
        std::string str_buffer = get_range(pos, len);
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
  void check_bounds(std::size_t pos) const {
    if (pos >= m_buf.size()) {
      throw std::out_of_range("BytePacketBuffer: end of buffer");
    }
  }

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

  void read(BytePacketBuffer& buffer) {
    id = buffer.read_u16();

    std::uint16_t flags = buffer.read_u16();
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

    questions = buffer.read_u16();
    answers = buffer.read_u16();
    authoritative_entries = buffer.read_u16();
    resource_entries = buffer.read_u16();
  }

  friend std::ostream& operator<<(std::ostream& os, const DnsHeader& h) {
    os << "ID: " << h.id << "\n"
       << "QR: " << h.response << " OPCODE: " << (int)h.opcode << " AA: " << h.authoritative_answer << "\n"
       << "TC: " << h.truncated_message << " RD: " << h.recursion_desired << " RA: " << h.recursion_available << "\n"
       << "Questions: " << h.questions << " Answers: " << h.answers << "\n"
       << "Authoritative: " << h.authoritative_entries << " Additional: " << h.resource_entries;
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

struct DnsQuestion {
  std::string name;
  QueryType qtype;

  void read(BytePacketBuffer& buffer) {
    name = buffer.read_qname();
    qtype = from_num(buffer.read_u16());
    buffer.read_u16();  // skip class
  }

  friend std::ostream& operator<<(std::ostream& os, const DnsQuestion& q) {
    os << q.name << " type=" << to_num(q.qtype);
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
};

struct UnknownRecord {
  std::string domain;
  std::uint16_t qtype;
  std::uint16_t data_len;
  std::uint32_t ttl;
};

using DnsRecord = std::variant<ARecord, UnknownRecord>;

DnsRecord read_dns_record(BytePacketBuffer& buffer) {
  std::string domain = buffer.read_qname();

  std::uint16_t qtype_num = buffer.read_u16();
  QueryType qtype = from_num(qtype_num);
  buffer.read_u16();  // 跳过 class（忽略）
  std::uint32_t ttl = buffer.read_u32();
  std::uint16_t data_len = buffer.read_u16();

  switch (qtype) {
    case QueryType::A: {
      std::uint32_t raw_addr = buffer.read_u32();
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

  void from_buffer(BytePacketBuffer& buffer) {
    header.read(buffer);

    for (int i = 0; i < header.questions; i++) {
      DnsQuestion question{};
      question.read(buffer);
      questions.push_back(question);
    }

    for (int i = 0; i < header.answers; i++) {
      answers.emplace_back(read_dns_record(buffer));
    }

    for (int i = 0; i < header.authoritative_entries; i++) {
      authorities.emplace_back(read_dns_record(buffer));
    }

    for (int i = 0; i < header.resource_entries; i++) {
      resources.emplace_back(read_dns_record(buffer));
    }
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
  packet.from_buffer(buffer);

  std::cout << "\n=== Header ===" << std::endl;
  std::cout << packet.header << std::endl;

  std::cout << "\n=== Questions (" << packet.questions.size() << ") ===" << std::endl;
  for (const auto& q : packet.questions) {
    std::cout << "  " << q << std::endl;
  }

  auto print_records = [](const std::string& label, const std::vector<DnsRecord>& records) {
    std::cout << "\n=== " << label << " (" << records.size() << ") ===" << std::endl;
    for (const auto& rec : records) {
      std::visit(overloaded{
                     [](const ARecord& r) {
                       std::cout << "  " << r.domain << " A " << r.addr.to_string() << " TTL=" << r.ttl << std::endl;
                     },
                     [](const UnknownRecord& r) {
                       std::cout << "  " << r.domain << " type=" << r.qtype << " len=" << r.data_len << " TTL=" << r.ttl
                                 << std::endl;
                     },
                 },
                 rec);
    }
  };

  print_records("Answers", packet.answers);
  print_records("Authorities", packet.authorities);
  print_records("Resources", packet.resources);

  return 0;
}
