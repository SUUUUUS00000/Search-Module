#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "httplib.h"
#include "luau_filter.hpp" // с 3 правками для InputFormat (Base64 / Hex / Auto)

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

static void append_json_str(std::string& out, std::string_view s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

static luau_filter::InputFormat parse_fmt(std::string_view s) noexcept {
    if (s == "raw")    return luau_filter::InputFormat::Raw;
    if (s == "base64") return luau_filter::InputFormat::Base64;
    if (s == "hex")    return luau_filter::InputFormat::Hex;
    return luau_filter::InputFormat::Auto;
}

int main() {
    httplib::Server svr;

    // 4 рабочих потока + лимит 16 МБ: безопасно укладывается в 512 МБ RAM на Render
    svr.new_task_queue = [] { return new httplib::ThreadPool(4); };
    svr.set_payload_max_length(16 * 1024 * 1024);

    auto health_handler = [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"ok\":true,\"version\":\"4.5.0\"}", "application/json");
    };
    svr.Get("/", health_handler);
    svr.Get("/health", health_handler);

    // POST /words?format=auto|base64|hex|raw&tokens=0|1
    // Тело запроса (body): байткод в любом поддерживаемом формате
    svr.Post("/words", [](const httplib::Request& req, httplib::Response& res) {
        if (req.body.empty()) {
            res.status = 400;
            res.set_content("{\"ok\":false,\"error\":\"empty body\"}", "application/json");
            return;
        }

        // Независимый экземпляр на поток (без блокировок), сброс кэша каждые 512 запросов
        thread_local luau_filter::BytecodeFilter engine;
        thread_local size_t req_count = 0;
        if (++req_count >= 512) {
            engine.clear();
            req_count = 0;
        }

        const auto fmt = req.has_param("format")
            ? parse_fmt(req.get_param_value("format"))
            : luau_filter::InputFormat::Auto;

        const bool want_tokens = req.has_param("tokens") && req.get_param_value("tokens") == "1";

        const auto* patterns = engine.words(req.body, fmt);
        if (!patterns) {
            res.status = 400;
            res.set_content("{\"ok\":false,\"error\":\"invalid bytecode\"}", "application/json");
            return;
        }

        std::string json;
        json.reserve(patterns->size() * 20 + 64);
        json += "{\"ok\":true,\"patterns\":[";
        for (size_t i = 0; i < patterns->size(); ++i) {
            if (i > 0) json.push_back(',');
            append_json_str(json, (*patterns)[i]);
        }
        json.push_back(']');

        if (want_tokens) {
            const auto* toks = engine.tokens(req.body, fmt);
            json += ",\"tokens\":[";
            if (toks) {
                for (size_t i = 0; i < toks->size(); ++i) {
                    if (i > 0) json.push_back(',');
                    append_json_str(json, (*toks)[i]);
                }
            }
            json.push_back(']');
        }

        json.push_back('}');
        res.set_content(std::move(json), "application/json");
    });

    int port = 10000;
    if (const char* env_p = std::getenv("PORT")) {
        int p = std::atoi(env_p);
        if (p > 0 && p <= 65535) port = p;
    }

    std::cout << "Listening on 0.0.0.0:" << port << std::endl;
    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "Failed to bind port " << port << std::endl;
        return 1;
    }
    return 0;
}