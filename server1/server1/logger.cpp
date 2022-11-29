#include "logger.h"
#include "define.h"
#include <chrono>
#include <boost/filesystem.hpp>
#include <iostream>
#include <stdarg.h>

#ifdef WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif


LOGGER* LOGGER::m_instance = nullptr;  //define a static member variable
std::mutex LOGGER::m_mutex;
std::mutex LOGGER::m_queuemutex;
std::condition_variable LOGGER::m_con;
std::queue<LOG> LOGGER::m_queue;
std::map<LOGLEVEL, std::string> LOGGER::m_levelnamemap{
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_TRACE, "TRACE"),
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_DEBUG, "DEBUG"),
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_INFO,  "INFO"),
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_WARN,  "WARN"),
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_ERROR, "ERROR"),
        std::pair<LOGLEVEL, std::string>(LOGLEVEL::LOG_LEVEL_FATAL, "FATAL"),
};

LOGGER* LOGGER::GetInstance()
{
    if (m_instance == nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_instance == nullptr) {
            LOGGER* temp = new LOGGER();
            m_instance = temp;
        }
    }
    return m_instance;
}

void LOGGER::Init(LOGLEVEL loglevel, LOGTARGET logtarget, std::string logpath)
{
    m_loglevel = loglevel;
    m_logtarget = logtarget;
    m_logFilePath = logpath;
    
}

bool LOGGER::JudgePath(std::string path)
{
    boost::filesystem::path full_path(boost::filesystem::initial_path());
    full_path = boost::filesystem::system_complete(boost::filesystem::path(path));
    //判断各级子目录是否存在，不存在则需要创建
    return boost::filesystem::exists(full_path);
}

bool LOGGER::JudgeFile(std::string filepath)
{
    boost::filesystem::path path_file(filepath);
    if (boost::filesystem::exists(path_file) && boost::filesystem::is_regular_file(path_file))
    {
        return true;
    }

    return false;
}

bool LOGGER::CreatePath(std::string path)
{
    boost::filesystem::path full_path(boost::filesystem::initial_path());
    full_path = boost::filesystem::system_complete(boost::filesystem::path(path));
    //判断各级子目录是否存在，不存在则需要创建
    if (!boost::filesystem::exists(full_path))
    {
        // 创建多层子目录
        bool bRet = boost::filesystem::create_directories(full_path);   //可以创建多级目录
        return bRet;

    }

    return true;
}

bool LOGGER::CreateFiles(std::string dirpath, std::string filename)
{
    if (!JudgePath(dirpath))
    {
        if (!CreatePath(dirpath))
        {
            return false;
        }
    }

    std::string filepath = dirpath + "/" + filename;

    if (!JudgeFile(filepath))
    {
        FILE *fd = fopen(filepath.c_str(), "a");
        if (fd)
        {
            fclose(fd);
            return true;
        }

        return false;
    }

    return true;
}

std::string LOGGER::CreateDefaultPath()
{
    std::string exePath = boost::filesystem::initial_path<boost::filesystem::path>().string();  //获取程序当前执行路径
    std::replace(exePath.begin(), exePath.end(), '\\', '/');
    std::string newPath = exePath + "/log";
    std::cout << newPath << std::endl;
    exePath = newPath;
    std::string filename = GetTimeToDay();
    filename += ".log";

    if (CreateFiles(exePath, filename))
    {
        newPath += "/" + filename;
        return newPath;
    }

    return "";
}

LOGLEVEL LOGGER::GetLogLevel()
{
    return m_loglevel;
}

void LOGGER::SetLogLevel(LOGLEVEL loglevel)
{
    m_loglevel = loglevel;
}

int LOGGER::GetLogTarget()
{
    return m_logtarget;
}

void LOGGER::SetLogTarget(LOGTARGET logtarget)
{
    m_logtarget |= logtarget;
}

void LOGGER::Reset()
{
    m_loglevel = LOG_LEVEL_INFO;
    m_logtarget = LOG_TARGET_FILE;
    m_logFilePath = "";
}

std::string LOGGER::GetLogPath()
{
    return m_logFilePath;
}

void LOGGER::SetLogPath(std::string logpath)
{
    m_logFilePath = logpath;
}

int LOGGER::WriteLog(LOGLEVEL loglevel, std::string filename, std::string functionname, int lineNumber, char* format, ...)
{
    int ret = 0;

    std::string currenttime = GetTimeToMillisecond();
    
    std::string level = m_levelnamemap[loglevel];



#ifndef __linux__
    std::string processid = std::to_string(GetCurrentProcessId());
    std::string threadid = std::to_string(GetCurrentThreadId());

#else
    std::string processid = std::to_string(getpid());
    std::string threadid = std::to_string(gettid());
#endif

    std::string basiclinfo = "[PID: " + processid + "][TID: " + threadid + "][" + level + "][" + filename + "][" + functionname + " : " + std::to_string(lineNumber) + "]";

    std::string buffer = "";
    buffer += currenttime + "  ";
    buffer += basiclinfo;

    char logInfo[1024];
    memset(logInfo, 0, 1024);
    va_list ap;
    va_start(ap, format);
    ret = vsnprintf(logInfo, 256, format, ap);
    va_end(ap);

    buffer += logInfo;
    buffer += "\n";

    if (m_logFilePath == "")
    {
        m_logFilePath = CreateDefaultPath();
        std::cout << m_logFilePath << std::endl;
        if (m_logFilePath == "")
        {
            return -1;
        }
    }

    std::cout << "default success:" << m_logFilePath << std::endl;
    if ((m_logtarget & LOG_TARGET_FILE) && !JudgeFile(m_logFilePath))
    {
        return -1;
    }
    
    {
        LOG log;
        log.content = buffer;
        log.filePath = m_logFilePath;
        log.mode = m_logtarget;
        std::lock_guard<std::mutex> locker(m_queuemutex);
        m_queue.emplace(log);
        std::cout << "emplace success" << std::endl;
        
    }
    OutputTarget();
    return 0;
}

void LOGGER::OutputTarget()
{
    LOG log;
    {
        std::unique_lock<std::mutex> locker(m_queuemutex);
        m_con.wait(locker, [] {return !m_queue.empty(); });
        log = m_queue.front();
        m_queue.pop();
    }
    
    if (log.mode & LOG_TARGET_CONSOLE)
    {
        std::cout << log.content << std::endl;
    }
    if (log.mode & LOG_TARGET_FILE)
    {
        FILE* fd = nullptr;
        fd = fopen(log.filePath.c_str(), "a");
        if (fd != nullptr)
        {
            fwrite(log.content.c_str(), 1, log.content.size(), fd);
            fclose(fd);
        }
    }
    
}

LOGGER::LOGGER():m_loglevel{LOG_LEVEL_DEBUG}, m_logtarget{LOG_TARGET_FILE}, m_logFilePath{""}
{
}

std::string LOGGER::GetTimeToMillisecond()
{
    auto now = std::chrono::system_clock::now();
    //通过不同精度获取相差的毫秒数
    uint64_t dis_millseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()
        - std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() * 1000;
    time_t tt = std::chrono::system_clock::to_time_t(now);
    auto time_tm = localtime(&tt);
    char strTime[25] = { 0 };
    sprintf(strTime, "%d-%02d-%02d %02d:%02d:%02d %03d", time_tm->tm_year + 1900,
        time_tm->tm_mon + 1, time_tm->tm_mday, time_tm->tm_hour,
        time_tm->tm_min, time_tm->tm_sec, (int)dis_millseconds);

    std::string result = strTime;
    return result;
}

std::string LOGGER::GetTimeToDay()
{
    auto now = std::chrono::system_clock::now();
    //通过不同精度获取相差的毫秒数
    uint64_t dis_millseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()
        - std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() * 1000;
    time_t tt = std::chrono::system_clock::to_time_t(now);
    auto time_tm = localtime(&tt);
    char strTime[25] = { 0 };
    sprintf(strTime, "%d%02d%02d", time_tm->tm_year + 1900,
        time_tm->tm_mon + 1, time_tm->tm_mday);

    std::string result = strTime;
    return result;
}
