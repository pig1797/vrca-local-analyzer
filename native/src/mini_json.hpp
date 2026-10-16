#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace vrc::json {

class Value {
public:
    using Object = std::map<std::string, Value>;
    using Array = std::vector<Value>;
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Object, Array>;

    Value() : value_(nullptr) {}
    Value(std::nullptr_t) : value_(nullptr) {}
    Value(bool value) : value_(value) {}
    Value(int value) : value_(static_cast<double>(value)) {}
    Value(std::int64_t value) : value_(static_cast<double>(value)) {}
    Value(double value) : value_(value) {}
    Value(const char* value) : value_(std::string(value)) {}
    Value(std::string value) : value_(std::move(value)) {}
    Value(Object value) : value_(std::move(value)) {}
    Value(Array value) : value_(std::move(value)) {}

    bool is_object() const;
    bool is_array() const;
    bool is_string() const;
    bool is_number() const;
    bool is_bool() const;
    bool is_null() const;
    Object& object();
    const Object& object() const;
    Array& array();
    const Array& array() const;
    const std::string& string() const;
    double number(double fallback = 0.0) const;
    bool boolean(bool fallback = false) const;
    const Value* find(const std::string& key) const;
    Value& operator[](const std::string& key);
    std::string dump(int indent = 2) const;

private:
    Storage value_;
};

Value Parse(const std::string& text);

}  // namespace vrc::json
