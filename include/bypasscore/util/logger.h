#pragma once

#include <string>
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <fstream>
#include <chrono>
#include <ctime>
#include <memory>

namespace bypasscore {

enum class LogLevel : int {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4,
    Fatal = 5,
    Off   = 6
};

inline const char* log_level_str(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        default:              return "?????";
    }
}

/**
 * @brief Thread-safe logger with file and console output support.
 *
 * Singleton logger with configurable log level, optional file output,
 * and timestamped formatted messages.
 */
class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void set_level(LogLevel level) { min_level_ = level; }
    LogLevel level() const { return min_level_; }

    void set_console_output(bool enabled) { console_ = enabled; }

    bool open_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        file_.open(path, std::ios::app);
        return file_.is_open();
    }

    void close_file() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) file_.close();
    }

    void log(LogLevel level, const char* file, int line, const char* fmt, ...) {
        if (level < min_level_) return;

        char msg_buf[2048];
        va_list args;
        va_start(args, fmt);
        vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
        va_end(args);

        // Build timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        char time_buf[64];
        struct tm tm_buf;
#ifdef _WIN32
        localtime_s(&tm_buf, &time_t_now);
#else
        localtime_r(&time_t_now, &tm_buf);
#endif
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

        // Extract filename from path
        const char* fname = file;
        for (const char* p = file; *p; ++p) {
            if (*p == '/' || *p == '\') fname = p + 1;
        }

        char line_buf[4096];
        snprintf(line_buf, sizeof(line_buf), "[%s.%03d] [%s] [%s:%d] %s\n",
                 time_buf, static_cast<int>(ms.count()),
                 log_level_str(level), fname, line, msg_buf);

        std::lock_guard<std::mutex> lock(mutex_);
        if (console_) {
            std::fputs(line_buf, (level >= LogLevel::Error) ? stderr : stdout);
        }
        if (file_.is_open()) {
            file_ << line_buf;
            file_.flush();
        }
    }

private:
    Logger() : min_level_(LogLevel::Info), console_(true) {}
    ~Logger() { close_file(); }

    LogLevel min_level_;
    bool console_;
    std::mutex mutex_;
    std::ofstream file_;
};

#define BC_LOG(level, fmt, ...) \
    ::bypasscore::Logger::instance().log(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define BC_TRACE(fmt, ...) BC_LOG(::bypasscore::LogLevel::Trace, fmt, ##__VA_ARGS__)
#define BC_DEBUG(fmt, ...) BC_LOG(::bypasscore::LogLevel::Debug, fmt, ##__VA_ARGS__)
#define BC_INFO(fmt, ...)  BC_LOG(::bypasscore::LogLevel::Info,  fmt, ##__VA_ARGS__)
#define BC_WARN(fmt, ...)  BC_LOG(::bypasscore::LogLevel::Warn,  fmt, ##__VA_ARGS__)
#define BC_ERROR(fmt, ...) BC_LOG(::bypasscore::LogLevel::Error, fmt, ##__VA_ARGS__)
#define BC_FATAL(fmt, ...) BC_LOG(::bypasscore::LogLevel::Fatal, fmt, ##__VA_ARGS__)

} // namespace bypasscore
