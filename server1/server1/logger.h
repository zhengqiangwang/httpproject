#ifndef LOGGER_H
#define LOGGER_H

#include <mutex>
#include <queue>
#include <map>
#include <condition_variable>

//定义日志等级
enum LOGLEVEL
{
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_TRACE,
};

//日志输出地方
enum LOGTARGET
{
	LOG_TARGET_CONSOLE	= 1 << 0,
	LOG_TARGET_FILE		= 1 << 1,
	LOG_TARGET_NONE		= 1 << 2,
};

//保存一条日志信息
struct LOG
{
	std::string content;
	int mode;
	std::string filePath;
};


class LOGGER
{
public:
	//获取单例类的对象
	static LOGGER* GetInstance();

	//初始化日志对象
	void Init(LOGLEVEL loglevel, LOGTARGET logtarget, std::string logpath);

	//判断路径是否存在
	bool JudgePath(std::string path);

	//判断文件是否存在
	bool JudgeFile(std::string filepath);

	//创建指定的路径
	bool CreatePath(std::string path);

	//创建文件根据目录和文件名
	bool CreateFiles(std::string dirpath, std::string filename);

	//根据时间创建默认日志存储路径
	std::string CreateDefaultPath();

	//获取日志等级
	LOGLEVEL GetLogLevel();

	//设置日志等级
	void SetLogLevel(LOGLEVEL loglevel);

	//获取日志输出目标
	int GetLogTarget();

	//设置日志输出目标
	void SetLogTarget(LOGTARGET logtarget);

	//恢复默认设置
	void Reset();

	//获取日志存储路径
	std::string GetLogPath();

	//设置日志存储路径
	void SetLogPath(std::string logpath);

	//根据设定生成日志信息并压入队列
	int WriteLog(LOGLEVEL loglevel, std::string filename, std::string functionname, int lineNumber, char* format, ...);

	//将队列中的日志信息输出到指定位置
	void OutputTarget();

private:
	//构造函数
	LOGGER();

	//获取精确到毫秒的时间
	std::string GetTimeToMillisecond();

	//获取精确到天的时间
	std::string GetTimeToDay();

private:
	static LOGGER* m_instance;									//declare a static member variable  
	static std::mutex m_mutex;									//在构建对象时防止多次生成用的互斥量
	static std::mutex m_queuemutex;								//用户包含日志信息队列的互斥量
	static std::condition_variable m_con;						//通过条件变量来控制队列的读写
	static std::queue<LOG> m_queue;								//用来保存日志信息的队列
	static std::map<LOGLEVEL, std::string> m_levelnamemap;		//用来保存日志等级对应的描述
	LOGLEVEL m_loglevel;										//用来保存日志等级
	int m_logtarget;											//用来保存日志输出目标
	std::string m_logFilePath;									//用来保存日志文件的路径
};

#endif //LOGGER_H
