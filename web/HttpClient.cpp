#include "stdafx.h"
#include "httpclient.h"  
#include <shlobj.h>
#include "openssl/crypto.h"

CURLSH *CHttpClient::m_curlsh = NULL;
static HANDLE *s_lock_cs;

// needed by openssl in multi-threaded case
void OPENSSL_MT_LockingCallBack(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		WaitForSingleObject(s_lock_cs[type], INFINITE);
	}
	else
	{
		ReleaseMutex(s_lock_cs[type]);
	}
}

bool OPENSSL_MT_Setup()
{
	int i;

	s_lock_cs = (HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
	if (s_lock_cs == NULL)
	{
		return false;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		s_lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
	}

	CRYPTO_set_locking_callback(OPENSSL_MT_LockingCallBack);
	/* id callback defined */
	return true;
}

void OPENSSL_MT_Cleanup()
{
	int i;
	if (s_lock_cs == NULL)
	{
		return;
	}
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		CloseHandle(s_lock_cs[i]);
	}
	OPENSSL_free(s_lock_cs);
}

bool CHttpClient::Init()
{
	bool bRet = false;
	CURLcode code_global;
	do 
	{
		if (!OPENSSL_MT_Setup())
		{
			break;
		}
		code_global = curl_global_init(CURL_GLOBAL_ALL);
		if (CURLE_OK != code_global)
		{
			break;
		}
		m_curlsh = curl_share_init();
		if (NULL == m_curlsh)
		{
			break;
		}
		curl_share_setopt(m_curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

		bRet = true;

	} while (0);

	if (!bRet)
	{
		if (m_curlsh)
		{
			curl_share_cleanup(m_curlsh);
		}
		if (CURLE_OK == code_global)
		{
			curl_global_cleanup();
		}
	}

	return bRet;
}

void CHttpClient::UnInit()
{
	if (m_curlsh)
	{
		curl_share_cleanup(m_curlsh);
	}
	curl_global_cleanup();
	OPENSSL_MT_Cleanup();
}

CHttpClient::CHttpClient(void) : 
	m_bDebug(false), 
	m_bFollowRedirect(false), 
	m_bVerifyCert(false), 
	m_bTLS(false),
	m_iRetryCount(1),
	m_strProxy(""),
	m_strProxyUserPwd(""),
	m_ulProxyAuth(CURLAUTH_ANY),
	m_strUserAgent("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)")
{  
	m_curl = curl_easy_init();

	m_strDebug = "";
	m_strLastUrl = "";
	m_strRedirectUrl = "";
	m_fTotalTime = 0;	
	long m_nStatusCode = -1;
	m_strIp = "";
	long m_nPort = -1;
}
  
CHttpClient::~CHttpClient(void)  
{  
	if (m_curl)
	{
		curl_easy_cleanup(m_curl);
	}
}  
  
int OnDebug(CURL *, curl_infotype itype, char *pData, size_t size, void *lpVoid)  
{  
	std::string *str = dynamic_cast<std::string *>((std::string *)lpVoid);
	if (str == NULL)
	{
		return 0;
	}
	str->clear();
	str->append(pData, size);

    if(itype == CURLINFO_TEXT)  
    {  
        //printf("[TEXT]\n%s\n", str->c_str());  
    } else if(itype == CURLINFO_HEADER_IN)  
    {  
        printf("%s", str->c_str());  
    } else if(itype == CURLINFO_HEADER_OUT)  
    {  
        printf("%s", str->c_str());  
    } else if(itype == CURLINFO_DATA_IN)  
    {  
        //printf("[DATA_IN]\n%s\n", str->c_str());  
    } else if(itype == CURLINFO_DATA_OUT)  
    {  
        //printf("[DATA_OUT]\n%s\n", str->c_str());  
    }  
    return 0;  
}  
  
size_t OnWriteDataAsString(void *buffer, size_t size, size_t nmemb, void *lpVoid)  
{  
    std::string *str = dynamic_cast<std::string *>((std::string *)lpVoid);  
    if(NULL == str || NULL == buffer)  
    {  
        return -1;  
    }  
  
    char *pData = (char *)buffer;  
    str->append(pData, size * nmemb);  
    return nmemb;  
}

size_t OnWriteDataAsFile(void *buffer, size_t size, size_t nmemb, void *lpVoid)
{
	FILE *fp = dynamic_cast<FILE *>((FILE *)lpVoid); 
	if (NULL == fp)
	{
		return -1;
	}
	fwrite(buffer, size, nmemb, fp);
	return nmemb;
}
  
int CHttpClient::DoGetStringByPost(const std::string &strUrl, const std::string &strPostData, std::string &strResponse)  
{  
	return DoGetStringByPostEx(strUrl, strPostData, strResponse, NULL, NULL, NULL); 
} 

int CHttpClient::DoGetStringByPostEx(const std::string &strUrl, const std::string &strPostData, std::string &strResponse, 
									 const char *pszReferer, const char *pszContentType, const char *pszMethod)
{
	CURLcode res;  
	CURL *curl = (CURL *)GetInstance(false); 
	struct curl_slist *slist = NULL;
	strResponse.clear();

	if(NULL == curl)  
	{  
		return CURLE_FAILED_INIT;  
	}  
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());  
	curl_easy_setopt(curl, CURLOPT_POST, 1);  
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strPostData.c_str());  
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&strResponse);  
	if ((pszReferer != NULL) && (strlen(pszReferer) != 0))
	{
		curl_easy_setopt(curl, CURLOPT_REFERER, pszReferer);
	}
	if (pszContentType != NULL)
	{
		std::string strHeader = "Content-Type: ";
		strHeader += pszContentType;
		slist = curl_slist_append(slist, strHeader.c_str());
		if (slist)
		{
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
		}
	}
	if (pszMethod != NULL)
	{
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, pszMethod);
	}
	res = DoQuery(curl);  
	if (CURLE_OK == res)
	{
		DealWithResponse(curl);
	}
	if (slist)
	{
		curl_slist_free_all(slist);
	}
	curl_easy_cleanup(curl);  
	return res;  
}
static size_t read_callback(void* ptr,size_t size,size_t nmemb,void *stream)
{
	size_t retcode;
	retcode = fread(ptr,size,nmemb,(FILE*)stream);
	return retcode;
}

bool CHttpClient::DoPutFileToServer(const std::string &strUrl,const std::string &file)
{
	CURL *curl;
	CURLcode res;
	FILE* hd_src;
	hd_src = fopen(file.c_str(),"rb");
	if(hd_src == NULL) return false;
	long dwFileSize=0;
	fseek(hd_src,0,SEEK_END);
	dwFileSize=ftell(hd_src);
	rewind(hd_src);
	curl=curl_easy_init();
	if(curl)
	{
		curl_easy_setopt(curl,CURLOPT_READFUNCTION,read_callback);
		curl_easy_setopt(curl,CURLOPT_UPLOAD,1L);
		curl_easy_setopt(curl,CURLOPT_PUT,1L);
		curl_easy_setopt(curl,CURLOPT_URL,strUrl.c_str());
		curl_easy_setopt(curl,CURLOPT_READDATA,hd_src);
		curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,(curl_off_t)dwFileSize);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}
	fclose(hd_src);
	if(res != CURLE_OK)
		return false;
	else
		return true;
}
int CHttpClient::DoGetStringByGet(const std::string &strUrl, std::string &strResponse,bool bSaveHeader)  
{  
	return DoGetStringByGetEx(strUrl, strResponse, NULL,bSaveHeader);
}  

int CHttpClient::DoGetStringByGetEx(const std::string &strUrl, std::string &strResponse, const char *pszReferer,bool bSaveHeader)
{
	CURLcode res;  
	CURL *curl = (CURL *)GetInstance(false);  
	strResponse.clear();

	if(NULL == curl)  
	{  
		return CURLE_FAILED_INIT;  
	}  
	if (bSaveHeader)
	{
		curl_easy_setopt(curl,CURLOPT_HEADER,1);
	}
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());  
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&strResponse); 
	if ((pszReferer != NULL) && (strlen(pszReferer) != 0))
	{
		curl_easy_setopt(curl, CURLOPT_REFERER, pszReferer);
	}
	if (!addCookie.empty())
	{
		curl_easy_setopt(curl,CURLOPT_COOKIE,addCookie.c_str());
		addCookie="";
	}
	res = DoQuery(curl);  
	if (CURLE_OK == res)
	{
		DealWithResponse(curl);
	}
	curl_easy_cleanup(curl);  
	return res;  
}

int CHttpClient::DoGetFileByPost(const std::string &strUrl, const std::string &strPostData, const std::wstring &strFile)
{
	return DoGetFileByPostEx(strUrl, strPostData, strFile, NULL, NULL, NULL); 
}

int CHttpClient::DoGetFileByPostEx(const std::string &strUrl, const std::string &strPostData, const std::wstring &strFile, 
								   const char *pszReferer, const char *pszContentType, const char *pszMethod)
{
	CURLcode res;  
	CURL *curl = (CURL *)GetInstance(true); 
	FILE *fp = NULL;
	struct curl_slist *slist = NULL;

	if(NULL == curl)  
	{  
		return CURLE_FAILED_INIT;  
	}  

	do 
	{
		fp = GetSaveFile(strFile);
		if (fp == NULL)
		{
			res = CURLE_WRITE_ERROR;
			break;
		}
		curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());  
		curl_easy_setopt(curl, CURLOPT_POST, 1);  
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strPostData.c_str());  
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)fp);  
		if ((pszReferer != NULL) && (strlen(pszReferer) != 0))
		{
			curl_easy_setopt(curl, CURLOPT_REFERER, pszReferer);
		}
		if (pszContentType != NULL)
		{
			std::string strHeader = "Content-Type: ";
			strHeader += pszContentType;
			slist = curl_slist_append(slist, strHeader.c_str());
			if (slist)
			{
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
			}
		}
		if (pszMethod != NULL)
		{
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, pszMethod);
		}
		res = DoQuery(curl);  
		if (CURLE_OK == res)
		{
			DealWithResponse(curl);
		}  
	} while (0);
	if (fp)
	{
		fclose(fp);
	}
	if (slist)
	{
		curl_slist_free_all(slist);
	}
	if (curl)
	{
		curl_easy_cleanup(curl);
	}
	if (res != CURLE_OK)
	{
		DeleteFileW(strFile.c_str());
	}
	return res;  	
}

int CHttpClient::DoGetFileByGet(const std::string &strUrl, const std::wstring &strFile)
{
	return DoGetFileByGetEx(strUrl, strFile, NULL);
}

int CHttpClient::DoGetFileByGetEx(const std::string &strUrl, const std::wstring &strFile, const char *pszReferer)
{
	CURLcode res;  
	CURL *curl = (CURL *)GetInstance(true);  
	FILE *fp = NULL;
	if(NULL == curl)  
	{  
		return CURLE_FAILED_INIT;  
	}  

	do 
	{
		fp = GetSaveFile(strFile);
		if (fp == NULL)
		{
			res = CURLE_WRITE_ERROR;
			break;
		}
		curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());  
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)fp);  
		if ((pszReferer != NULL) && (strlen(pszReferer) != 0))
		{
			curl_easy_setopt(curl, CURLOPT_REFERER, pszReferer);
		}
		res = DoQuery(curl);
		if (CURLE_OK == res)
		{
			DealWithResponse(curl);
		} 
	} while (0);
	if (fp)
	{
		fclose(fp);
	}
	if (curl)
	{
		curl_easy_cleanup(curl);
	}
	if (res != CURLE_OK)
	{
		DeleteFileW(strFile.c_str());
	}
	return res; 
}

FILE *CHttpClient::GetSaveFile(const std::wstring &strFile)
{
	FILE *fp = NULL;
	wchar_t szPath[MAX_PATH];
	const wchar_t *pBS = NULL;
	const wchar_t *pFile = strFile.c_str();
	pBS = wcsrchr(pFile, L'\\');
	if (pBS)
	{
		wcsncpy_s(szPath, MAX_PATH, pFile, pBS - pFile);
		MakeSureDirectory(szPath);
	}
	_wfopen_s(&fp, pFile, L"wb");
	return fp;
}

void CHttpClient::MakeSureDirectory(const wchar_t *lpDir)
{
	if (!IsDirectoryExist(lpDir))
	{
		SHCreateDirectoryExW(NULL, lpDir, NULL);
	}
}

bool CHttpClient::IsDirectoryExist(const wchar_t *lpDir)
{
	WIN32_FIND_DATAW FindData;
	HANDLE hFind = FindFirstFileW(lpDir, &FindData);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		return false;
	}
	bool ret = false;
	if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		ret = true;
	}
	FindClose(hFind);
	return ret;
}

CURLcode CHttpClient::DoQuery(CURL *curl)
{
	CURLcode res;
	int iRetry = m_iRetryCount;
	while (iRetry)
	{
		res = curl_easy_perform(curl);
		if (res == CURLE_OK)
		{
			break;
		}
		--iRetry;
	}

	return res;
}

CURL *CHttpClient::GetInstance(bool bSaveResponseAsFile)
{
	CURL *curl = curl_easy_init();  
	if(NULL == curl)  
	{  
		return NULL;  
	}  
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);  
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);  
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 300);  
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300);  
	if (bSaveResponseAsFile)
	{
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteDataAsFile); 	
	} else
	{
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnWriteDataAsString); 
	}
	if(m_bDebug)  
	{  
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);  
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, OnDebug); 
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, (void *)&m_strDebug);
	}  
	if(!m_bVerifyCert)  
	{  
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);  
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);  
	} 
	if (m_bFollowRedirect)
	{
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
		curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_GET_ALL);
	}
	if (m_bTLS)
	{
		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
	}

	// proxy setting
	if (m_strProxy.length() != 0)
	{
		curl_easy_setopt(curl, CURLOPT_PROXY, m_strProxy.c_str());
		curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, m_strProxyUserPwd.c_str());
		curl_easy_setopt(curl, CURLOPT_PROXYAUTH, m_ulProxyAuth);
		curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1); // set for imap/pop3
	}

	// enable cookie engine
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); 
	//
	curl_easy_setopt(curl, CURLOPT_USERAGENT, m_strUserAgent.c_str());
	//
	curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
	// share dns
	curl_easy_setopt(curl, CURLOPT_SHARE, m_curlsh);
	//
	// curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "c:\\test.txt");

	AddBuiltInCookie(curl);
	AddUserCookie(curl);

	return curl;
}

void CHttpClient::AddBuiltInCookie(CURL *curl)
{
	for (BuiltInCookieArrayIter it = m_aryBuiltInCookie.begin(); it != m_aryBuiltInCookie.end(); it++)
	{
		curl_easy_setopt(curl, CURLOPT_COOKIELIST, it->c_str());
	}
}

void CHttpClient::SaveBuiltInCookie(CURL *curl)
{
	struct curl_slist *pCookieList = NULL;

	m_aryBuiltInCookie.clear();

	curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &pCookieList);
	struct curl_slist *pCur = pCookieList;
	while (pCur)
	{
		m_aryBuiltInCookie.push_back(pCur->data);
		//printf("NetscapeCookie: %s\r\n", pCur->data);
		pCur = pCur->next;
	}
	curl_slist_free_all(pCookieList);
}

void CHttpClient::AddUserCookie(CURL *curl)
{
	char szTemp[30];
	for (size_t i = 0; i < m_aryUserCookie.size(); i++)
	{
		std::string strCookie;
		
		strCookie = m_aryUserCookie[i].bHttpOnly ? "#HttpOnly_" : ""; 
		strCookie += "." + m_aryUserCookie[i].strDomain + "\t";
		
		strCookie += "TRUE\t";
		
		strCookie += m_aryUserCookie[i].strPath + "\t";
		
		strCookie += (m_aryUserCookie[i].bSecure ? "TRUE" : "FALSE");
		strCookie += "\t";
		
		sprintf_s(szTemp, sizeof(szTemp), "%ld", m_aryUserCookie[i].expires);
		strCookie += szTemp;
		strCookie += "\t";
		
		strCookie += m_aryUserCookie[i].strName + "\t";
		
		strCookie += m_aryUserCookie[i].strValue;

		curl_easy_setopt(curl, CURLOPT_COOKIELIST, strCookie.c_str());
	}
	m_aryUserCookie.clear();
}

/*
// from curl
static char *get_netscape_format(const struct Cookie *co)
{
  return aprintf(
    "%s"     // httponly preamble 
    "%s%s\t" // domain 
    "%s\t"   // tailmatch 
    "%s\t"   // path 
    "%s\t"   // secure 
    "%ld\t"   // expires 
    "%s\t"   // name 
    "%s",    // value 
    co->httponly?"#HttpOnly_":"",    
    (co->tailmatch && co->domain && co->domain[0] != '.')? ".":"", // Make sure all domains are prefixed with a dot if they allow tailmatching. This is Mozilla-style.
    co->domain?co->domain:"unknown",
    co->tailmatch?"TRUE":"FALSE",
    co->path?co->path:"/",
    co->secure?"TRUE":"FALSE",
    co->expires,
    co->name,
    co->value?co->value:"");
}
*/

void CHttpClient::SetOptVerifyCert(bool bVerifyCert)
{
	m_bVerifyCert = bVerifyCert;
}

void CHttpClient::SetOptFollowRedirect(bool bFollowRedirect)
{
	m_bFollowRedirect = bFollowRedirect;
}
void CHttpClient::SetOptSSLByTLS(bool bTLS)
{
	m_bTLS = bTLS;
}

void CHttpClient::SetDebug(bool bDebug)  
{  
    m_bDebug = bDebug;  
} 

void CHttpClient::SetRetryCount(int iCount)
{
	m_iRetryCount = iCount;
}

void CHttpClient::SetOptProxy(const char *p)
{
	if (p != NULL)
	{
		m_strProxy = p;
	} else
	{
		m_strProxy = "";
	}
}

void CHttpClient::SetOptProxyUserPwd(const char *p)
{
	if (p != NULL)
	{
		m_strProxyUserPwd = p;
	} else
	{
		m_strProxyUserPwd = "";
	}
}

void CHttpClient::SetOptProxyAuth(unsigned long auth)
{
	m_ulProxyAuth = auth;
}

void CHttpClient::SetOptUserAgent(const char *p)
{
	if (p != NULL)
	{
		m_strUserAgent = p;
	}
}

void CHttpClient::AddUserCookie(const std::string &strName, const std::string strValue, const std::string &strPath, const std::string &strDomain, bool bHttpOnly, bool bSecure, unsigned long expires)
{
	UserCookie uc;
	uc.strName = strName;
	uc.strValue = strValue;
	uc.strPath = strPath;
	uc.strDomain = strDomain;
	uc.bHttpOnly = bHttpOnly;
	uc.bSecure = bSecure;
	uc.expires = expires;
	m_aryUserCookie.push_back(uc);
}

void CHttpClient::EncodeURI(std::string &str)
{
	char *p = NULL;
	p = NewEscaped(str.c_str(), str.length());
	if (p)
	{
		str = p;
		Free(p);
	}
}

void CHttpClient::DecodeURI(std::string &str)
{
	char *p = NULL;
	p = NewUnescaped(str.c_str(), str.length());
	if (p)
	{
		str = p;
		Free(p);
	}
}

void CHttpClient::AppendPlain(std::string &str, const char *p)
{
	str += p;
}

void CHttpClient::AppendPlain(std::string &str, const std::string &s)
{
	str += s;
}

void CHttpClient::AppendEscaped(std::string &str, const std::string &s)
{
	AppendEscaped(str, s.c_str(), s.length());
}

void CHttpClient::AppendEscaped(std::string &str, const char *p, int len)
{
	char *pEscaped = NULL;
	pEscaped = NewEscaped(p, len);
	if (pEscaped)
	{
		str += pEscaped;
		Free(pEscaped);
	}
}

void CHttpClient::AppendKeyValue(std::string &str, const std::string &strKey, const std::string &strValue, bool bStartWithAnd)
{
	if (bStartWithAnd)
	{
		str += "&";
	}
	AppendEscaped(str, strKey);
	str += "=";
	AppendEscaped(str, strValue);
}

void CHttpClient::GetLastUrl(std::string &str)
{
	str = m_strLastUrl;
}

void CHttpClient::GetRedirectUrl(std::string &str)
{
	str = m_strRedirectUrl;
}

void CHttpClient::GetErrorString(std::string &str, int res)
{
	str = curl_easy_strerror((CURLcode)res);
}

double CHttpClient::GetTotalTime()
{
	return m_fTotalTime;
}

char *CHttpClient::NewEscaped(const char *p, int len)
{
	if (m_curl)
	{
		return curl_easy_escape(m_curl, p, len);
	}
	return NULL;
}

char *CHttpClient::NewUnescaped(const char *p, int len)
{
	if (m_curl)
	{
		return curl_easy_unescape(m_curl, p, len, NULL);
	}
	return NULL;
}

void CHttpClient::Free(char *p)
{
	if (m_curl)
	{
		if (p)
		{
			curl_free(p);
		}
	}
}

void CHttpClient::DealWithResponse(CURL *curl)
{
	CURLcode res;
	char *pLastUrl = NULL;
	char *pRedirectUrl = NULL; 
	double fTime = 0;
	long nState = -1;
	char *pIp = NULL;
	long nPort = -1;

	m_strLastUrl = "";
	m_strRedirectUrl = "";

	res = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &pLastUrl);
	if ((CURLE_OK == res) && pLastUrl)
	{
		m_strLastUrl = pLastUrl;
	}
	res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &pRedirectUrl);
	if ((CURLE_OK == res) && pRedirectUrl)
	{
		m_strRedirectUrl = pRedirectUrl;
	}
	res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &fTime);
	m_fTotalTime += fTime;

	res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &nState);
	m_nStatusCode = nState;

	res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &pIp);
	m_strIp = pIp;

	res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &nPort);
	m_nPort = nPort;

	if (m_bDebug)
	{
		printf("[time]: %fs\n", fTime);
	}
	
	SaveBuiltInCookie(curl);
}

std::string CHttpClient::GetCookieString()
{
	std::string tmpCookie;
	BuiltInCookieArrayIter it=m_aryBuiltInCookie.begin();
	for (;it!=m_aryBuiltInCookie.end() ; it++)
	{
		tmpCookie=tmpCookie+*it+"; ";
	}
	return tmpCookie;
}

void CHttpClient::SetCookieString( std::string cookie )
{
	addCookie=cookie;
}

long CHttpClient::GetStatusCode()
{
	return m_nStatusCode;
}

std::string CHttpClient::GetRemoteIp()
{
	return m_strIp;
}

long CHttpClient::GetRemotePort()
{
	return m_nPort;
}

CHttpClientEx::CHttpClientEx() : CHttpClient()
{
	
}

CHttpClientEx::~CHttpClientEx()
{

}

int CHttpClientEx::DoProtoLogin(const std::string &strUrl, const std::string &strUser, const std::string &strPass)
{
	CURLcode res;  
	CURL *curl = (CURL *)GetInstance(false);  

	if(NULL == curl)  
	{  
		return CURLE_FAILED_INIT;  
	}  
	std::string strUserPwd = strUser + ":" + strPass;
	curl_easy_setopt(curl, CURLOPT_USERPWD, strUserPwd.c_str());
	curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());  
	res = curl_easy_perform(curl); // we don't want to retry query here
	curl_easy_cleanup(curl);  
	return res;  
}

HTTPCLIENT_API bool __stdcall InitHttpClient()
{
	return CHttpClient::Init();
}

HTTPCLIENT_API void __stdcall UnInitHttpClient()
{
	CHttpClient::UnInit();
}

HTTPCLIENT_API IHttpClient* __stdcall CreateHttpClient()
{
	return new CHttpClientEx;
}

HTTPCLIENT_API void __stdcall DestroyHttpClient(IHttpClient *pHttpClient)
{
	if (pHttpClient)
	{
		delete pHttpClient;
	}
}
