#include "curlhttp.h"
#include <string.h>
#include <iostream>
#include "define.h"

CurlHttp::CurlHttp() : m_curl{ nullptr }, m_response{ "" }, m_res{ CURLE_OK }, m_curlHeaders{ nullptr }, m_receiveLength{ 0 }
{

}

CurlHttp::~CurlHttp()
{
	if (m_curl != nullptr)
	{
		curl_easy_cleanup(m_curl);
		m_curl = nullptr;
	}

	if (m_curlHeaders != nullptr)
	{
		curl_slist_free_all(m_curlHeaders);
		m_curlHeaders = nullptr;
	}
}

bool CurlHttp::SendPost(void)
{
	bool result = false;

	result = ConstructPost();
	if (!result)
	{
		return result;
	}

	result = WriteData();

	return result;
}

bool CurlHttp::SendGet(void)
{
	bool result = false;

	result = ConstructGet();
	if (!result)
	{
		return result;
	}

	result = WriteData();

	return result;
}

size_t CurlHttp::ReceiveData(void* ptr, size_t size, size_t nmemb, void* stream)
{
	size_t realSize = size * nmemb;
	std::string* str = (std::string*)stream;
	(*str).append((char*)ptr, realSize);

	return size * nmemb;
}

bool CurlHttp::ConstructGet()
{
	m_curl = curl_easy_init();
	if (m_curl)
	{
		//构建HTTP报文头
		m_curlHeaders = nullptr;
		std::string header = "";
		for (auto& m : m_requestHeader)
		{
			header = m.first + ": " + m.second;
			m_curlHeaders = curl_slist_append(m_curlHeaders, header.c_str());
		}

		//设置HTTP头
		curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_curlHeaders);

		//curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 1L);
		//curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L);
		//设置发送超时时间
		curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, 20L);

		curl_easy_setopt(m_curl, CURLOPT_CAINFO, CLIENT_CA_FILE);
		curl_easy_setopt(m_curl, CURLOPT_SSLCERT, CLIENT_CERT_FILE);
		curl_easy_setopt(m_curl, CURLOPT_SSLKEY, CLIENT_KEY_FILE);

		//设置请求方法
		curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "GET");

		//设置post请求的url地址
		std::string url = "https://" + m_ip + ":" + std::to_string(m_port) + m_url;
		curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());


		curl_easy_setopt(m_curl, CURLOPT_VERBOSE, 1L);

		//设置返回头部信息
		curl_easy_setopt(m_curl, CURLOPT_HEADER, true);

		//执行单条请求
		curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, ReceiveData);//设置回调函数
		curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, (void*)&m_response);
	}
	else
	{
		return false;
	}

	return true;
}

bool CurlHttp::ConstructPost()
{
	m_curl = curl_easy_init();
	if (m_curl)
	{
		//构建HTTP报文头
		m_curlHeaders = nullptr;
		std::string header = "";
		for (auto& m : m_requestHeader)
		{
			header = m.first + ": " + m.second;
			m_curlHeaders = curl_slist_append(m_curlHeaders, header.c_str());
		}

		if (m_contentLength > 1024)
		{
			m_curlHeaders = curl_slist_append(m_curlHeaders, "Expect:");
		}

		//设置HTTP头
		curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_curlHeaders);

		//curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 0L);
		//curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L);
		//设置发送超时时间
		curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, 20L);

		curl_easy_setopt(m_curl, CURLOPT_CAINFO, CLIENT_CA_FILE);
		curl_easy_setopt(m_curl, CURLOPT_SSLCERT, CLIENT_CERT_FILE);
		curl_easy_setopt(m_curl, CURLOPT_SSLKEY, CLIENT_KEY_FILE);

		//设置请求方法
		curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "POST");

		//设置post请求的url地址
		std::string url = "https://" + m_ip + ":" + std::to_string(m_port) + m_url;
		//std::cout << "url:---------------------------------\n" << url << std::endl;
		curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());


		curl_easy_setopt(m_curl, CURLOPT_VERBOSE, 1L);

		//设置返回头部信息
		curl_easy_setopt(m_curl, CURLOPT_HEADER, true);

		//构建回调函数
		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, m_content);
		curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, m_contentLength);
		curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, ReceiveData);//设置回调函数
		curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, (void*)&m_response);
	}
	else
	{
		return false;
	}

	return true;
}

bool CurlHttp::WriteData()
{
	m_response = "";
	m_res = curl_easy_perform(m_curl);
	//std::cout <<"m_curl response:"<< m_res <<"m_curl ok:"<<CURLE_OK<< std::endl;
	if (m_res != CURLE_OK) {
		//curl_easy_strerror进行出错打印
		return false;
	}

	m_receiveLength = 0;

	m_res = curl_easy_getinfo(m_curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &m_receiveLength);

	long ul = 0;
	curl_easy_getinfo(m_curl, CURLINFO_HEADER_SIZE, &ul);
	m_receiveLength += ul;
	//这个调用用来结束一个会话.与curl_easy_init配合着用

	if (m_res != CURLE_OK)
	{
		return false;
	}

	if (m_curlHeaders != nullptr)
	{
		curl_slist_free_all(m_curlHeaders);
		m_curlHeaders = nullptr;

	}
	//std::cout<<"m_curl end1"<<std::endl;
	if (m_curl != nullptr)
	{
		curl_easy_cleanup(m_curl);
		m_curl = nullptr;
		//std::cout << "m_curl end" << std::endl;
	}
	m_readIndex = 0;
	return true;
}

int CurlHttp::ReadData(char* outData, int readLength, bool flag)
{
	if (outData == nullptr || readLength < 0)
	{
		return -1;
	}
	if (m_readIndex < m_receiveLength)
	{
		if (m_receiveLength - m_readIndex >= readLength)
		{
			memcpy(outData, m_response.c_str() + m_readIndex, readLength);
			m_readIndex += readLength;
			return readLength;
		}
		else
		{
			memcpy(outData, m_response.c_str() + m_readIndex, m_receiveLength - m_readIndex);
			return m_receiveLength - m_readIndex;
		}
	}

	return 0;
}

