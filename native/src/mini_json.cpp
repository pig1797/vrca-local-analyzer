#include "mini_json.hpp"

#include "common.hpp"

#include <cmath>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace vrc::json {

bool Value::is_object() const { return std::holds_alternative<Object>(value_); }
bool Value::is_array() const { return std::holds_alternative<Array>(value_); }
bool Value::is_string() const { return std::holds_alternative<std::string>(value_); }
bool Value::is_number() const { return std::holds_alternative<double>(value_); }
bool Value::is_bool() const { return std::holds_alternative<bool>(value_); }
bool Value::is_null() const { return std::holds_alternative<std::nullptr_t>(value_); }
Value::Object& Value::object() { if (!is_object()) value_ = Object{}; return std::get<Object>(value_); }
const Value::Object& Value::object() const { return std::get<Object>(value_); }
Value::Array& Value::array() { if (!is_array()) value_ = Array{}; return std::get<Array>(value_); }
const Value::Array& Value::array() const { return std::get<Array>(value_); }
const std::string& Value::string() const { return std::get<std::string>(value_); }
double Value::number(double fallback) const { return is_number() ? std::get<double>(value_) : fallback; }
bool Value::boolean(bool fallback) const { return is_bool() ? std::get<bool>(value_) : fallback; }
const Value* Value::find(const std::string& key) const {
    if (!is_object()) return nullptr;
    const auto it = object().find(key);
    return it == object().end() ? nullptr : &it->second;
}
Value& Value::operator[](const std::string& key) { return object()[key]; }

namespace {

void DumpValue(const Value& value, std::ostringstream& out, int indent, int depth) {
    const auto pad = [&](int extra = 0) { out << std::string(static_cast<std::size_t>((depth + extra) * indent), ' '); };
    if (value.is_null()) out << "null";
    else if (value.is_bool()) out << (value.boolean() ? "true" : "false");
    else if (value.is_number()) {
        const double n = value.number();
        if (!std::isfinite(n)) throw std::runtime_error("JSON non-finite number");
        if (std::floor(n) == n) out << std::fixed << std::setprecision(0) << n;
        else out << std::defaultfloat << std::setprecision(std::numeric_limits<double>::max_digits10) << n;
    } else if (value.is_string()) out << '"' << JsonEscape(value.string()) << '"';
    else if (value.is_array()) {
        out << '[';
        if (!value.array().empty()) {
            for (std::size_t i = 0; i < value.array().size(); ++i) {
                out << (i ? "," : "") << '\n'; pad(1);
                DumpValue(value.array()[i], out, indent, depth + 1);
            }
            out << '\n'; pad();
        }
        out << ']';
    } else {
        out << '{';
        std::size_t i = 0;
        for (const auto& [key, item] : value.object()) {
            out << (i++ ? "," : "") << '\n'; pad(1);
            out << '"' << JsonEscape(key) << "\": ";
            DumpValue(item, out, indent, depth + 1);
        }
        if (!value.object().empty()) { out << '\n'; pad(); }
        out << '}';
    }
}

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}
    Value parse() { skip(); Value value = parse_value(); skip(); if (pos_ != text_.size()) fail("trailing data"); return value; }

private:
    const std::string& text_;
    std::size_t pos_ = 0;

    [[noreturn]] void fail(const char* message) const { throw std::runtime_error(std::string("JSON ") + message + " at byte " + std::to_string(pos_)); }
    void skip() {
        while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                text_[pos_] == '\n' || text_[pos_] == '\r')) ++pos_;
    }
    bool take(char ch) { skip(); if (pos_ < text_.size() && text_[pos_] == ch) { ++pos_; return true; } return false; }
    Value parse_value(std::size_t depth = 0) {
        skip(); if (pos_ >= text_.size()) fail("unexpected end");
        const char ch = text_[pos_];
        if ((ch == '{' || ch == '[') && depth >= 128) fail("nesting limit exceeded");
        if (ch == '{') return parse_object(depth + 1);
        if (ch == '[') return parse_array(depth + 1);
        if (ch == '"') return Value(parse_string());
        if (ch == 't' && text_.compare(pos_, 4, "true") == 0) { pos_ += 4; return Value(true); }
        if (ch == 'f' && text_.compare(pos_, 5, "false") == 0) { pos_ += 5; return Value(false); }
        if (ch == 'n' && text_.compare(pos_, 4, "null") == 0) { pos_ += 4; return Value(nullptr); }
        if (ch == '-' || (ch >= '0' && ch <= '9')) return parse_number();
        fail("invalid value");
    }
    Value parse_object(std::size_t depth) {
        take('{'); Value::Object result; skip();
        if (take('}')) return Value(std::move(result));
        while (true) {
            skip(); if (pos_ >= text_.size() || text_[pos_] != '"') fail("object key expected");
            std::string key = parse_string(); if (!take(':')) fail("colon expected");
            Value item = parse_value(depth);
            if (!result.emplace(std::move(key), std::move(item)).second)
                fail("duplicate object key");
            if (take('}')) break;
            if (!take(',')) fail("comma expected");
        }
        return Value(std::move(result));
    }
    Value parse_array(std::size_t depth) {
        take('['); Value::Array result; skip();
        if (take(']')) return Value(std::move(result));
        while (true) { result.push_back(parse_value(depth)); if (take(']')) break; if (!take(',')) fail("comma expected"); }
        return Value(std::move(result));
    }
    unsigned hex_quad() {
        if (pos_ + 4 > text_.size()) fail("short unicode escape");
        unsigned code = 0;
        for (int i = 0; i < 4; ++i) {
            const char h = text_[pos_++]; code <<= 4;
            if (h >= '0' && h <= '9') code += h - '0';
            else if (h >= 'a' && h <= 'f') code += h - 'a' + 10;
            else if (h >= 'A' && h <= 'F') code += h - 'A' + 10;
            else fail("bad unicode escape");
        }
        return code;
    }
    std::string parse_string() {
        if (!take('"')) fail("string expected");
        std::string out;
        while (pos_ < text_.size()) {
            char ch = text_[pos_++]; if (ch == '"') return out;
            if (static_cast<unsigned char>(ch) < 0x20) fail("unescaped control character");
            if (ch != '\\') { out.push_back(ch); continue; }
            if (pos_ >= text_.size()) fail("bad escape");
            const char esc = text_[pos_++];
            switch (esc) {
                case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break; case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break; case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned code = hex_quad();
                    if (code >= 0xD800 && code <= 0xDBFF) {
                        if (text_.compare(pos_, 2, "\\u") != 0) fail("missing low surrogate");
                        pos_ += 2;
                        const unsigned low = hex_quad();
                        if (low < 0xDC00 || low > 0xDFFF) fail("bad low surrogate");
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                    } else if (code >= 0xDC00 && code <= 0xDFFF) fail("unpaired low surrogate");
                    if (code <= 0x7F) out.push_back(static_cast<char>(code));
                    else if (code <= 0x7FF) { out.push_back(static_cast<char>(0xC0 | (code >> 6))); out.push_back(static_cast<char>(0x80 | (code & 0x3F))); }
                    else if (code <= 0xFFFF) { out.push_back(static_cast<char>(0xE0 | (code >> 12))); out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F))); out.push_back(static_cast<char>(0x80 | (code & 0x3F))); }
                    else { out.push_back(static_cast<char>(0xF0 | (code >> 18))); out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F))); out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F))); out.push_back(static_cast<char>(0x80 | (code & 0x3F))); }
                    break;
                }
                default: fail("unknown escape");
            }
        }
        fail("unterminated string");
    }
    Value parse_number() {
        const std::size_t start = pos_; if (text_[pos_] == '-') ++pos_;
        const auto digit = [&] { return pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9'; };
        if (!digit()) fail("integer part expected");
        if (text_[pos_] == '0') ++pos_;
        else while (digit()) ++pos_;
        if (digit()) fail("leading zero");
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_; if (!digit()) fail("fraction expected");
            while (digit()) ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            if (!digit()) fail("exponent expected");
            while (digit()) ++pos_;
        }
        std::istringstream input(text_.substr(start, pos_ - start));
        input.imbue(std::locale::classic());
        double number = 0;
        input >> number;
        if (!input || !input.eof() || !std::isfinite(number)) fail("bad number");
        return Value(number);
    }
};

}  // namespace

std::string Value::dump(int indent) const { std::ostringstream out; out.imbue(std::locale::classic()); DumpValue(*this, out, indent, 0); return out.str(); }
Value Parse(const std::string& text) { return Parser(text).parse(); }

}  // namespace vrc::json
