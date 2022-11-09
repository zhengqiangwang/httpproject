#include "http.h"
#include <iostream>
#include <cstring>
#include <openssl/ssl.h>

Http::Http() : m_requestContent{ nullptr }, m_requestContentLength{ 0 }, m_replyContent{ nullptr },
m_replyContentLength{ 0 }, m_socketFd{ -1 }, m_bufferSize{ 4096 }, m_tmpBuffer{ new char[m_bufferSize] }
{

}

Http::~Http()
{
	if (m_socketFd != -1)
	{
#ifdef WIN32
		closesocket(m_socketFd);
#else
		close(m_socketFd);
#endif

	}

	delete[] m_tmpBuffer;

	if (m_requestContent)
	{
		delete[] m_requestContent;
		m_requestContent = nullptr;
	}

	if (m_replyContent)
	{
		delete[] m_replyContent;
		m_replyContent = nullptr;
	}
}

bool Http::SendReply()
{
	bool result = false;

	result = ConstructReply();
	if (result)
	{
		std::cout << "Costructreply success:" <<m_replyLength<< std::endl;
		result = WriteData(m_socketFd, m_reply, m_replyLength);
	}

	return result;
}

void Http::Init(int sockfd, const sockaddr_in& address, SSL **ssl)
{
	m_socketFd = sockfd;
	m_address = address;
	m_ssl = *ssl;
	InitDescription(m_description);
}

bool Http::SetReplyHeader(std::string key, std::string value)
{
	if (m_replyHeader.count(key))
	{
		return false;
	}
	m_replyHeader[key] = value;
	return true;
}

std::string Http::GetRequestHeader(std::string key)
{
	std::string result = "";
	if (!m_requestHeader.count(key))
	{
		return result;
	}
	result = m_requestHeader[key];
	return result;
}

bool Http::SetReplyContent(const char* content, int len)
{
	if (!content || len <= 0)
	{
		return false;
	}

	if (m_replyContent)
	{
		delete[] m_replyContent;
		m_replyContent = nullptr;
	}

	m_replyContent = new char[len];
	memset(m_replyContent, 0, len);
	memcpy(m_replyContent, content, len);
	m_replyContentLength = len;

	return true;
}

char* Http::GetRequestContent()
{
	if (!m_requestContent)
	{
		return nullptr;
	}
	return m_requestContent;
}


bool Http::AcquireRequest()
{
	ClearRequest();
	if (ParseRequest() == ENTIRE_REQUEST)
	{
		return true;
	}

	return false;
}

std::string Http::GetReplyHeader(std::string key)
{
	std::string result = "";
	if (!m_replyHeader.count(key))
	{
		return result;
	}
	result = m_replyHeader[key];
	return result;
}

char* Http::GetReplyContent()
{
	return m_replyContent;
}

int Http::GetReplyContentLen()
{
	return m_replyContentLength;
}

int Http::GetRequestContentLen(void)
{
	return m_requestContentLength;
}

void Http::ClearRequest()
{
	if (m_requestContent)
	{
		delete[] m_requestContent;
		m_requestContent = nullptr;
	}

	m_requestContentLength = 0;
	m_requestHeader.clear();
	m_url = "";
	m_checkIndex = 0;
	m_readIndex = 0;
}

void Http::ClearReply()
{
	if (m_replyContent)
	{
		delete[] m_replyContent;
		m_replyContent = nullptr;
	}
	m_replyContentLength = 0;
	m_replyHeader.clear();
	m_stateCode = 200;
}

bool Http::ConstructReply()
{
	std::string request = "";
	bool result = false;

	request = ConstructHeaderLine();
	request = ConstructHeaders(request);
	result = ConstructContent(request);

	return result;
}

std::string Http::GetMethod()
{
	return m_requestMethod;
}

std::string Http::GetUrl()
{
	return m_url;
}

bool Http::SetStateCode(int statecode)
{
	if (m_description.count(statecode))
	{
		m_stateCode = statecode;
		return true;
	}
	return false;
}

std::string Http::ConstructHeaderLine()
{
	std::string statueLine = "";

	if (m_httpVersion == "")
	{
		statueLine += "HTTP/1.1";
	}
	else
	{
		statueLine += m_httpVersion;
	}

	statueLine += " ";

	statueLine += std::to_string(m_stateCode) + " ";

	statueLine += m_description[m_stateCode];
	statueLine += "\r\n";

	return statueLine;
}

std::string Http::ConstructHeaders(std::string statueLine)
{
	std::string headers = statueLine;
	for (auto& m : m_replyHeader)
	{
		headers += m.first + ": " + m.second + "\r\n";
	}
	if (!m_replyHeader.count("Content-Length"))
	{
		headers += "Content-Length: " + std::to_string(m_replyContentLength) + "\r\n";
	}
	headers += "\r\n";

	return headers;
}

bool Http::ConstructContent(std::string headers)
{
	if (m_reply)
	{
		delete[] m_reply;
		m_reply = nullptr;
	}

	m_reply = new char[headers.size() + m_replyContentLength];
	memset(m_reply, 0, headers.size() + m_replyContentLength);
	memcpy(m_reply, headers.c_str(), headers.size());
	memcpy(m_reply + headers.size(), m_replyContent, m_replyContentLength);
	
	m_replyLength = headers.size() + m_replyContentLength;
	//std::cout << "header size:" << headers.size() << ", contentlen:" << m_replyContentLength << ", total len:" << m_replyLength << std::endl;

	return true;
}

bool Http::WriteData(int socketFd, const char* data, int writeLength)
{
	if (socketFd == -1 || writeLength <= 0)
	{
		return false;
	}

	int writeindex = 0;
	int writelen = 0;
	std::cout << "write m_ssl" << m_ssl << std::endl;
	//std::cout << "send length:" << writeLength << std::endl;
	//std::cout << data << std::endl;
	while (writeindex != writeLength) {
		writelen = SSL_write(m_ssl, data + writeindex, writeLength - writeindex);
		std::cout << "writelen: " << writelen << std::endl;

		if (writelen > 0)
		{
			writeindex += writelen;
		}
		else
		{
			int ret = SSL_get_error(m_ssl, writelen);
			std::cout << "write ret" << ret << std::endl;
			switch (ret)
			{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				continue;
				break;
			case SSL_ERROR_ZERO_RETURN:
				CloseLink(m_socketFd);
				return false;
				break;
			default:
				CloseLink(m_socketFd);
				return false;
				;
			}
		}

		std::cout <<"sendlen"<< writeLength << "writeindex: " << writeindex << std::endl;
	}
	
	return true;
}


/*
* 从套接字里读取readLength长度数据并将数据保存在outData中
*/

int Http::ReadData(int socketFd, char* outData, int readLength)
{
	if (socketFd == -1)
	{
		return -1;
	}


	int readindex = 0;
	int readlen = 0;
	std::cout << "read m_ssl" << m_ssl << std::endl;
	while (readindex != readLength)
	{
		//std::cout << "readLength" << readLength - readindex << std::endl;
		readlen = SSL_read(m_ssl, outData + readindex, readLength - readindex);
		std::cout << "readlen:" << readlen << std::endl;
		if (readlen > 0)
		{
			readindex += readlen;
		}
		else
		{
			int iErrno = errno;
			int iErrCode = SSL_get_error(m_ssl, readlen);
			std::cout << "read error" << iErrCode << std::endl;
			switch (iErrCode)
			{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				if (readindex > 0)   
				{
					return readindex;
				}
				std::cout<<"The operation did not complete; the same TLS/SSL I/O function should be called again later."<<std::endl;
				continue;
				break;
			case SSL_ERROR_ZERO_RETURN:
				std::cout << "ssl channel(fd %d) closed by peer." << std::endl;
				CloseLink(m_socketFd);
				return -1;
				break;
			case SSL_ERROR_SYSCALL:
				std::cout << "Some non-recoverable I/O error occurred. The OpenSSL error queue may contain more information on the error. "
					"For socket I/O on Unix systems, consult errno %d for details." << std::endl;
				CloseLink(m_socketFd);
				return -1;
				break;
			default:
				std::cout<<"SSL_read() error code %d, see SSL_get_error() manual for error code detail."<<std::endl;
				CloseLink(m_socketFd);
				return -1;
				;
			}
		}
	}
	//std::cout << "readindex" << readindex << std::endl;
	//std::cout << m_tmpBuffer << std::endl;
	return readindex;
}

void Http::CloseLink(int socketFd)
{
	std::cout << "close linke" << std::endl;
	if (socketFd != -1)
	{
#ifdef WIN32
		closesocket(socketFd);
#else
		close(socketFd);
#endif // WIN32

		socketFd = -1;
	}
}

bool Http::ModeEpollEvent(int epollfd, int fd, int type)
{
#ifndef WIN32
	epoll_event event;
	event.events = type;
	event.data.fd = fd;
	int ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);

	if (ret == 0)
	{
		return true;
	}
#endif
	return false;
}

Http::LINE_STATUS Http::ParseLine()
{
	char tmp;

	for (; m_checkIndex < m_readLength; m_checkIndex++) {
		tmp = m_tmpBuffer[m_checkIndex];
		if (tmp == '\r')
		{
			if (m_checkIndex < m_readLength - 1)
			{
				m_checkIndex++;
				tmp = m_tmpBuffer[m_checkIndex];
				if (tmp == '\n')
				{
					m_tmpBuffer[m_checkIndex - 1] = '\0';
					m_tmpBuffer[m_checkIndex] = '\0';
					m_checkIndex++;
					return LINE_ENTIRE;
				}
				else
				{
					return LINE_ERROR;
				}
			}
			else
			{
				return LINE_OPEN;
			}
		}
		else if (tmp == '\n')
		{
			if ((m_checkIndex > 1) && (m_tmpBuffer[m_checkIndex - 1] == '\r')) {
				m_tmpBuffer[m_checkIndex - 1] = '\0';
				m_tmpBuffer[m_checkIndex++] = '\0';
				return LINE_ENTIRE;
			}
			return LINE_ERROR;
		}
	}

	return LINE_OPEN;
}

char* Http::GetLine()
{
	return m_tmpBuffer + m_readIndex;
}

Http::HTTP_CODE Http::ParseRequest()
{
	m_readLength = ReadData(m_socketFd, m_tmpBuffer, m_bufferSize);
	m_checkState = CHECK_STATE_REQUESTLINE;
	LINE_STATUS line_statu = LINE_ENTIRE;
	HTTP_CODE ret = NOENTIRE_REQUEST;

	std::string text;
	while ((m_checkState == CHECK_STATE_CONTENT && line_statu == LINE_ENTIRE) || ((line_statu = ParseLine()) == LINE_ENTIRE))
	{
		text = GetLine();
		std::cout << m_checkState << " " << text.size() << ":" << text << std::endl;
		m_readIndex = m_checkIndex;
		switch (m_checkState)
		{
		case CHECK_STATE_REQUESTLINE:
		{
			ret = ParseRequestFirstLine(text);
			if (ret == SYNTAXERERROR_REQUEST)
			{
				return ret;
			}
			break;
		}
		case CHECK_STATE_HEADER:
		{
			ret = ParseHeader(text);
			if (ret == SYNTAXERERROR_REQUEST)
			{
				return ret;
			}
			else if (ret == ENTIRE_REQUEST)
			{
				return ret;
			}
			break;
		}
		case CHECK_STATE_CONTENT:
		{
			ret = ParseContent();
			if (ret == ENTIRE_REQUEST)
			{
				return ret;
			}
			line_statu = LINE_OPEN;
			break;
		}
		default:
			return INTERNAL_ERROR;
		}
	}
	return NOENTIRE_REQUEST;
}

Http::HTTP_CODE Http::ParseRequestFirstLine(std::string content)
{
	//std::cout << "parse first line" << std::endl;
	int left = SearchCharacter(content, 0);
	int right = SearchSpace(content, left);

	if (left == -1 || right == -1 || (right < left))
	{
		return SYNTAXERERROR_REQUEST;
	}

	m_requestMethod = content.substr(left, right - left);

	left = SearchCharacter(content, right);
	right = SearchSpace(content, left);

	if (left == -1 || right == -1 || (right < left))
	{
		return SYNTAXERERROR_REQUEST;
	}

	std::string url = "";
	url = content.substr(left, right - left).c_str();
	if (url[4] == ':')
	{
		url = url.substr(7);
	}
	//std::cout << "url" << url << std::endl;
	if (url.find('/') == std::string::npos)
	{
		return SYNTAXERERROR_REQUEST;
	}
	else
	{
		m_url = url.substr(url.find('/'));
	}

	left = SearchCharacter(content, right);
	if (left == -1)
	{
		return SYNTAXERERROR_REQUEST;
	}

	right = content.size();
	m_requestVersion = content.substr(left, right - left);

	m_checkState = CHECK_STATE_HEADER;
	//std::cout << m_url << std::endl;

	return NOENTIRE_REQUEST;
}

Http::HTTP_CODE Http::ParseHeader(std::string content)
{
	//std::cout << "parse header" << std::endl;
	int length = content.size();
	if (length == 0)
	{
		if (m_requestHeader.count("Content-Length") && atoi(m_requestHeader["Content-Length"].c_str()))
		{

			m_checkState = CHECK_STATE_CONTENT;
			return NOENTIRE_REQUEST;
		}

		return ENTIRE_REQUEST;
	}

	std::string key = "";
	std::string value = "";

	int i = 0;
	for (; i < length; i++)
	{
		if (content[i] != ' ')
		{
			break;
		}
	}

	if (i == length)
	{
		return SYNTAXERERROR_REQUEST;
	}
	int left = i;

	for (; i < length; i++)
	{
		if (content[i] == ' ' || content[i] == ':')
		{
			break;
		}
	}

	if (i == left || i == length)
	{
		return SYNTAXERERROR_REQUEST;
	}

	key = content.substr(left, i - left);

	if (content[i] == ' ')
	{
		for (; i < length; i++)
		{
			if (content[i] == ':')
			{
				break;
			}
		}

		if (i == length)
		{
			return SYNTAXERERROR_REQUEST;
		}
	}

	i++;

	left = SearchCharacter(content, i);
	if (left == -1)
	{
		return SYNTAXERERROR_REQUEST;
	}

	value = content.substr(left, length - left);


	m_requestHeader[key] = value;

	return NOENTIRE_REQUEST;
}

Http::HTTP_CODE Http::ParseContent()
{
	//std::cout << "parse content" << std::endl;
	int contentlength = atoi(m_requestHeader["Content-Length"].c_str());

	if (contentlength + m_checkIndex <= m_readLength)
	{
		if (m_requestHeader.find("Content-Type") != m_requestHeader.end() && m_requestHeader["Content-Type"] == "application/json")
		{
			m_requestContent = new char[contentlength + 1];
			memset(m_requestContent, 0, contentlength + 1);
		}
		else
		{
			m_requestContent = new char[contentlength];
			memset(m_requestContent, 0, contentlength);
		}
		memcpy(m_requestContent, m_tmpBuffer + m_readIndex, contentlength);
		m_requestContentLength = contentlength;

		return ENTIRE_REQUEST;
	}
	else
	{
		int length = m_readLength - m_readIndex;
		m_requestContent = new char[contentlength];
		memset(m_requestContent, 0, contentlength);
		memcpy(m_requestContent, m_tmpBuffer + m_readIndex, length);
		while (contentlength != length) {
			int relen = ReadData(m_socketFd, m_requestContent + length, contentlength - length);
			if (relen == -1)
			{
				return SYNTAXERERROR_REQUEST;
			}
			length += relen;
		}
		m_requestContentLength = contentlength;

		return  ENTIRE_REQUEST;
	}

	return ENTIRE_REQUEST;
}

int Http::SearchSpace(std::string& content, int start)
{
	int length = content.size();
	if (start >= length)
	{
		return -1;
	}

	if (start < 0)
	{
		start = 0;
	}

	for (int i = start; i < length; i++)
	{
		if (content[i] == ' ')
		{
			return i;
		}
	}

	return -1;
}

int Http::SearchCharacter(std::string& content, int start)
{
	int length = content.size();

	if (start >= length)
	{
		return -1;
	}

	if (start < 0)
	{
		start = 0;
	}

	for (int i = start; i < length; i++)
	{
		if (content[i] == ' ')
		{
			continue;
		}
		return i;
	}

	return -1;
}

void Http::InitDescription(std::unordered_map<int, std::string> &description)
{
	description.emplace(100, "Continue" );
	description.emplace(101, "Switching Protocols");
	description.emplace(200, "OK");
	description.emplace(201, "Created");
	description.emplace(202, "Accepted");
	description.emplace(203, "Non-Authoritative Information");
	description.emplace(204, "No Content");
	description.emplace(205, "Reset Content");
	description.emplace(206, "Partial Content");
	description.emplace(300, "Multiple Choices");
	description.emplace(301, "Moved Permanently");
	description.emplace(302, "Found");
	description.emplace(303, "See Other");
	description.emplace(304, "Not Modified");
	description.emplace(305, "Use Proxy");
	description.emplace(306, "Unused");
	description.emplace(307, "Temporary Redirect");
	description.emplace(400, "Bad Request");
	description.emplace(401, "Unauthorized");
	description.emplace(402, "Payment Required");
	description.emplace(403, "Forbidden");  
	description.emplace(404, "Not Found");
	description.emplace(405, "Method Not Allowed");
	description.emplace(406, "Not Acceptable");
	description.emplace(407, "Proxy Authentication Required");
	description.emplace(408, "Request Time-out");
	description.emplace(409, "Conflict");
	description.emplace(410, "Gone");
	description.emplace(411, "Length Required");
	description.emplace(412, "Precondition Failed");
	description.emplace(413, "Request Entity Too Large");
	description.emplace(414, "Request-URI Too Large");
	description.emplace(415, "Unsupported Media Type");
	description.emplace(416, "Requested range not satisfiable");
	description.emplace(417, "Expectation Failed");
	description.emplace(500, "Internal Server Error");
	description.emplace(501, "Not Implemented");
	description.emplace(502, "Bad Gateway");
	description.emplace(503, "Service Unavailable");
	description.emplace(504, "Gateway Time-out");
	description.emplace(505, "HTTP Version not supported");
}
