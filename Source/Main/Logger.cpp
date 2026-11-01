#include "Logger.hpp"
#include "../PostureBarMod.hpp"

namespace ER 
{
    std::string_view logLevelText(LogLevel logLevel)
    {
        switch (logLevel)
        {
            using enum LogLevel;

            case Log:
                return "Log    ";
            case Warning:
                return "Warning";
            case Error:
                return "Error  ";
            case Debug:
                return "Debug  ";

            default:
                return "       ";
        }
    }

    // "HH:MM:SS.mmm"
    std::string timeText()
    {
        SYSTEMTIME t;
        GetLocalTime(&t);
        char buffer[16];
        snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u.%03u", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        return buffer;
    }

    // "File.cpp:39" (file name only; the build machine's full path is noise)
    std::string locationText(const std::source_location& location)
    {
        std::string_view file = location.file_name();
        if (auto slash = file.find_last_of("\\/"); slash != std::string_view::npos)
            file.remove_prefix(slash + 1);
        return std::string(file) + ":" + std::to_string(location.line());
    }

    void Logger::log(const std::string_view& msg, LogLevel logLevel, const std::source_location& location)
    {
#ifndef DEBUGLOG
        if (logLevel == LogLevel::Debug)
            return;
#endif // DEBUGLOG

        if (!useLogger)
            return;

        std::scoped_lock lock(loggerMutex);
        if (!logFile.is_open())
            logFile.open(dllPath + logFileName, std::ifstream::out);

        if (logFile.good())
        {
            logFile << timeText() << " " << logLevelText(logLevel) << " " << locationText(location) << "  " << msg << "\n";
            logFile.flush();
        }
    }

    void Logger::close()
    {
        logFile.close();
    }
}
