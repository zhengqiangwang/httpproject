

#include <regex>
#include "http.h"
#include <iostream>
#include <curl/curl.h>
#include "define.h"

Http::Http() : m_ip{ "0.0.0.0" }, m_port{ 80 }, m_content{ nullptr }, m_contentLength{ 0 }, m_replyContent{ nullptr },
m_replyContentLength{ 0 }, m_bufferSize{ 4096 }, m_tmpBuffer{ new char[m_bufferSize] }
{
}

Http::~Http()
{
	delete[] m_tmpBuffer;

	if (m_content)
	{
		delete[] m_content;
		m_content = nullptr;
	}

	if (m_replyContent)
	{
		delete[] m_replyContent;
		m_replyContent = nullptr;
	}
}

bool Http::SendPost(void)
{
	return false;
}

bool Http::SendGet(void)
{
	return false;
}

bool Http::SetIpaddress(std::string ip)
{
	//    if(!CheckIPAddrIsVaild(ip))
	//    {
	//        return false;
	//    }
	m_ip = ip;
	return true;
}

bool Http::SetPort(int port)
{
	if (port < 0 || port > 65535)
	{
		return false;
	}
	m_port = port;
	return true;
}

bool Http::SetRequestHeader(std::string key, std::string value)
{
	if (m_requestHeader.count(key))
	{
		return false;
	}
	m_requestHeader[key] = value;
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

bool Http::SetRequestContent(const char* content, int len)
{
	if (!content || len <= 0)
	{
		return false;
	}

	if (m_content)
	{
		delete[] m_content;
		m_content = nullptr;
	}

	m_content = new char[len];
	memset(m_content, 0, len);
	memcpy(m_content, content, len);
	m_contentLength = len;

	return true;
}

char* Http::GetRequestContent()
{
	if (!m_content)
	{
		return nullptr;
	}
	return m_content;
}

bool Http::SetUrl(const std::string url)
{
	if (url == "")
	{
		return false;
	}

	m_url = url;
	return true;
}

bool Http::AcquireReply()
{
	if (m_replyContent)
	{
		delete[] m_replyContent;
		m_replyContent = nullptr;
	}


	m_readLength = ReadData(m_tmpBuffer, m_bufferSize, true);
	if (m_readLength < 0)
	{
		return false;
	}
	//std::cout << "---------------------------------------" << std::endl;
	//std::cout << m_tmpBuffer << std::endl;
	//std::cout << "---------------------------------------" << std::endl;
	//std::cout << "m_readLength" << m_readLength << std::endl;
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

void Http::ClearRequest()
{
	if (m_content)
	{
		delete[] m_content;
		m_content = nullptr;
	}

	m_contentLength = 0;
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
}

bool Http::CheckIPAddrIsVaild(std::string str)
{
	std::regex regExpress("(?=(\\b|\\D))(((\\d{1,2})|(1\\d{1,2})|(2[0-4]\\d)|(25[0-5]))\\.){3}((\\d{1,2})|(1\\d{1,2})|(2[0-4]\\d)|(25[0-5]))(?=(\\b|\\D))");
	return std::regex_match(str, regExpress);
}

bool Http::WriteData()
{
	return false;
}

int Http::ReadData(char* outData, int readLength, bool flag)
{
	return 0;
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
	m_checkState = CHECK_STATE_REQUESTLINE;
	LINE_STATUS line_statu = LINE_ENTIRE;
	HTTP_CODE ret = NOENTIRE_REQUEST;

	std::string text;
	while ((m_checkState == CHECK_STATE_CONTENT && line_statu == LINE_ENTIRE) || ((line_statu = ParseLine()) == LINE_ENTIRE))
	{
		text = GetLine();
		//std::cout << m_checkState << " " << text.size() << ":" << text << std::endl;
		m_readIndex = m_checkIndex;
		switch (m_checkState)
		{
		case CHECK_STATE_REQUESTLINE:
		{
			ret = ParseReplyFirstLine(text);
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

Http::HTTP_CODE Http::ParseReplyFirstLine(std::string content)
{
	int left = SearchCharacter(content, 0);
	int right = SearchSpace(content, left);

	if (left == -1 || right == -1 || (right < left))
	{
		return SYNTAXERERROR_REQUEST;
	}

	m_replyVersion = content.substr(left, right - left);

	left = SearchCharacter(content, right);
	right = SearchSpace(content, left);

	if (left == -1 || right == -1 || (right < left))
	{
		return SYNTAXERERROR_REQUEST;
	}

	m_stateCode = atoi(content.substr(left, right - left).c_str());

	left = SearchCharacter(content, right);
	if (left == -1)
	{
		return SYNTAXERERROR_REQUEST;
	}

	right = content.size();
	m_stateDescription = content.substr(left, right - left);

	m_checkState = CHECK_STATE_HEADER;

	return NOENTIRE_REQUEST;
}

Http::HTTP_CODE Http::ParseHeader(std::string content)
{
	int length = content.size();
	if (length == 0)
	{
		if (m_replyHeader.count("Content-Length") && atoi(m_replyHeader["Content-Length"].c_str()))
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


	m_replyHeader[key] = value;

	return NOENTIRE_REQUEST;
}

Http::HTTP_CODE Http::ParseContent()
{
	int contentlength = atoi(m_replyHeader["Content-Length"].c_str());

	if (contentlength + m_checkIndex <= m_readLength)
	{
		if (m_replyHeader.find("Content-Type") != m_replyHeader.end() && m_replyHeader["Content-Type"] == "application/json")
		{
			m_replyContent = new char[contentlength + 1];
			memset(m_replyContent, 0, contentlength + 1);
		}
		else
		{
			m_replyContent = new char[contentlength + 1];
			memset(m_replyContent, 0, contentlength + 1);
		}
		memcpy(m_replyContent, m_tmpBuffer + m_readIndex, contentlength);
		m_replyContentLength = contentlength;

		return ENTIRE_REQUEST;
	}
	else
	{
		int length = m_readLength - m_readIndex;
		m_replyContent = new char[contentlength + 1];
		memset(m_replyContent, 0, contentlength + 1);
		memcpy(m_replyContent, m_tmpBuffer + m_readIndex, length);
		while (contentlength != length) {
			int readlen = ReadData(m_replyContent + length, contentlength - length, false);//
			//int relen = ReadData(m_socketFd, m_replyContent + length, contentlength - length);
			if (readlen > 0)
			{
				length += readlen;
			}
			else
			{
				return NOENTIRE_REQUEST;
			}
		}
		m_replyContentLength = contentlength;

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
