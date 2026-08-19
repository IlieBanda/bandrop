#pragma once
#include <cctype>
#include <map>
#include <memory>
#include <string>
#include <vector>

// A tiny, self-contained JSON reader/writer — just enough for Bandrop's
// receipt files. Supports objects, arrays, strings, numbers, booleans and null.
namespace json {

struct Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>; // preserves order

struct Value {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::shared_ptr<Array> arr;
    std::shared_ptr<Object> obj;

    static Value S(const std::string& s) { Value v; v.type = Str; v.str = s; return v; }
    static Value N(double n) { Value v; v.type = Num; v.num = n; return v; }
    static Value B(bool x) { Value v; v.type = Bool; v.b = x; return v; }
    static Value A() { Value v; v.type = Arr; v.arr = std::make_shared<Array>(); return v; }
    static Value O() { Value v; v.type = Obj; v.obj = std::make_shared<Object>(); return v; }

    void set(const std::string& k, Value v) { obj->push_back({k, std::move(v)}); }
    void push(Value v) { arr->push_back(std::move(v)); }
    const Value* find(const std::string& k) const {
        if (type != Obj) return nullptr;
        for (auto& kv : *obj) if (kv.first == k) return &kv.second;
        return nullptr;
    }
};

// --- serialize -----------------------------------------------------------

inline void escape(const std::string& s, std::string& out) {
    out += '"';
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    out += '"';
}

inline void dump(const Value& v, std::string& out, int indent = 0) {
    std::string pad(indent, ' '), pad2(indent + 2, ' ');
    switch (v.type) {
        case Value::Null: out += "null"; break;
        case Value::Bool: out += v.b ? "true" : "false"; break;
        case Value::Num: {
            char b[32];
            if (v.num == (long long)v.num) snprintf(b, sizeof(b), "%lld", (long long)v.num);
            else snprintf(b, sizeof(b), "%g", v.num);
            out += b; break;
        }
        case Value::Str: escape(v.str, out); break;
        case Value::Arr:
            if (v.arr->empty()) { out += "[]"; break; }
            out += "[\n";
            for (size_t i = 0; i < v.arr->size(); ++i) {
                out += pad2; dump((*v.arr)[i], out, indent + 2);
                out += (i + 1 < v.arr->size()) ? ",\n" : "\n";
            }
            out += pad + "]"; break;
        case Value::Obj:
            if (v.obj->empty()) { out += "{}"; break; }
            out += "{\n";
            for (size_t i = 0; i < v.obj->size(); ++i) {
                out += pad2; escape((*v.obj)[i].first, out); out += ": ";
                dump((*v.obj)[i].second, out, indent + 2);
                out += (i + 1 < v.obj->size()) ? ",\n" : "\n";
            }
            out += pad + "}"; break;
    }
}

inline std::string dump(const Value& v) { std::string s; dump(v, s); return s; }

// --- parse ---------------------------------------------------------------

struct Parser {
    const char* p; const char* end; bool ok = true;
    Parser(const std::string& s) : p(s.data()), end(s.data() + s.size()) {}
    void ws() { while (p < end && std::isspace((unsigned char)*p)) ++p; }
    bool eat(char c) { ws(); if (p < end && *p == c) { ++p; return true; } return false; }

    Value parse() { Value v = value(); ws(); return v; }

    Value value() {
        ws();
        if (p >= end) { ok = false; return {}; }
        char c = *p;
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return Value::S(string());
        if (c == 't' || c == 'f') return boolean();
        if (c == 'n') { p += (end - p >= 4) ? 4 : (end - p); return {}; }
        return number();
    }
    Value object() {
        Value v = Value::O(); ++p; // {
        ws(); if (eat('}')) return v;
        for (;;) {
            ws(); if (p >= end || *p != '"') { ok = false; break; }
            std::string k = string();
            if (!eat(':')) { ok = false; break; }
            v.obj->push_back({k, value()});
            if (eat(',')) continue;
            if (eat('}')) break;
            ok = false; break;
        }
        return v;
    }
    Value array() {
        Value v = Value::A(); ++p; // [
        ws(); if (eat(']')) return v;
        for (;;) {
            v.arr->push_back(value());
            if (eat(',')) continue;
            if (eat(']')) break;
            ok = false; break;
        }
        return v;
    }
    std::string string() {
        std::string s; ++p; // opening quote
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) {
                ++p;
                switch (*p) {
                    case 'n': s += '\n'; break; case 't': s += '\t'; break;
                    case 'r': s += '\r'; break; case '"': s += '"'; break;
                    case '\\': s += '\\'; break; case '/': s += '/'; break;
                    default: s += *p;
                }
            } else s += *p;
            ++p;
        }
        if (p < end) ++p; // closing quote
        return s;
    }
    Value boolean() {
        if (end - p >= 4 && std::string(p, p + 4) == "true") { p += 4; return Value::B(true); }
        if (end - p >= 5 && std::string(p, p + 5) == "false") { p += 5; return Value::B(false); }
        ok = false; return {};
    }
    Value number() {
        const char* s = p;
        while (p < end && (std::isdigit((unsigned char)*p) || *p=='-'||*p=='+'||*p=='.'||*p=='e'||*p=='E')) ++p;
        if (p == s) { ok = false; return {}; }
        return Value::N(std::strtod(std::string(s, p).c_str(), nullptr));
    }
};

inline bool parse(const std::string& text, Value& out) {
    Parser pr(text);
    out = pr.parse();
    return pr.ok;
}

} // namespace json
