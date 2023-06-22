#pragma once

#define HTTPCLIENT_SELF_INCLUDE
#include "IHttpClient.h"
#include "IncLibCurl.h"
#include <vector>
#include "shlobj.h"


typedef struct tagUserCookie
{
	std::string strName;
	std::string strValue;
	std::string strPath;
	std::string strDomain;
	bool bHttpOnly;
	bool bSecure;
	unsigned long expires;
}UserCookie;

class CHttpClient : public IHttpClient
{  
public:
	// called once at application start
	static bool Init();
	// called once at application end
	static void UnInit();
public:  
    CHttpClient(void);  
    virtual ~CHttpClient(void);  
  
public:
	virtual int DoProtoLogin(const std::string &strUrl, const std::string &strUser, const std::string &strPass) = 0;

public:  
	// these functions does not reuse curl handles
    virtual int DoGetStringByPost(const std::string &strUrl, const std::string &strPostData, std::string &strResponse);
	// may need to use custom method in WebDAV protocol
	virtual int DoGetStringByPostEx(const std::string &strUrl, const std::string &strPostData, std::string &strResponse, 
		const char *pszReferer, const char *pszContentType, const char *pszMethod);
    virtual int DoGetStringByGet(const std::string &strUrl, std::string &strResponse,bool bSaveHeader=false); 

	virtual int DoGetStringByGetEx(const std::string &strUrl, std::string &strResponse, const char *pszReferer,bool bSaveHeader=false); 
	virtual int DoGetFileByPost(const std::string &strUrl, const std::string &strPostData, const std::wstring &strFile); 
	virtual int DoGetFileByPostEx(const std::string &strUrl, const std::string &strPostData, const std::wstring &strFile, 
		const char *pszReferer, const char *pszContentType, const char *pszMethod);
	virtual int DoGetFileByGet(const std::string &strUrl, const std::wstring &strFile); 
	virtual int DoGetFileByGetEx(const std::string &strUrl, const std::wstring &strFile, const char *pszReferer);
   virtual bool DoPutFileToServer(const std::string &strUrl,const std::string &file);
public:
	// 下面这些设置之后会一直采用, 
	//
    virtual void SetDebug(bool bDebug = false);  
	// default 1
	virtual void SetRetryCount(int iCount);
	// called before get or post
	virtual void SetOptVerifyCert(bool bVerifyCert = false);
	// 
	virtual void SetOptFollowRedirect(bool bFollowRedirect = false);
	// set ssl version
	virtual void SetOptSSLByTLS(bool bTLS = false);
	//
	virtual void SetOptProxy(const char *p);
	//
	virtual void SetOptProxyUserPwd(const char *p);
	//
	virtual void SetOptProxyAuth(unsigned long auth = CURLAUTH_ANY);
	//
	virtual void SetOptUserAgent(const char *p);

public: 
	//
	virtual void AddUserCookie(const std::string &strName, const std::string strValue, const std::string &strPath, const std::string &strDomain, bool bHttpOnly, bool bSecure, unsigned long expires);
	//
	virtual void EncodeURI(std::string &str);
	//
	virtual void DecodeURI(std::string &str);
	//
	virtual void AppendPlain(std::string &str, const char *p);
	//
	virtual void AppendPlain(std::string &str, const std::string &s);
	//
	virtual void AppendEscaped(std::string &str, const std::string &s);
	//
	virtual void AppendEscaped(std::string &str, const char *p, int len = 0);
	//
	virtual void AppendKeyValue(std::string &str, const std::string &strKey, const std::string &strValue, bool bStartWithAnd);
	//
	virtual void GetLastUrl(std::string &str);
	//
	virtual void GetRedirectUrl(std::string &str);
	//
	virtual void GetErrorString(std::string &str, int res);
	//
	virtual double GetTotalTime();

	virtual	std::string GetCookieString();

	virtual	void	SetCookieString(std::string cookie);

	virtual long GetStatusCode();

	virtual	std::string GetRemoteIp();

	virtual long GetRemotePort();

protected:
	// retry 1 times if failed 
	CURLcode DoQuery(CURL *curl);
	// return CURL * with default options set, ignore cert error, do not follow redirect, sslv3
	CURL *GetInstance(bool bSaveResponseAsFile);
	// make sure directory exist and open the file for write
	FILE *GetSaveFile(const std::wstring &strFile);
	// make sure directory exist
	void MakeSureDirectory(const wchar_t *lpDir);
	//
	bool IsDirectoryExist(const wchar_t *lpDir);
	// escape str with libcurl
	char *NewEscaped(const char *p, int len);
	// unescape str with libcurl
	char *NewUnescaped(const char *p, int len);
	// free str with libcurl
	void Free(char *p);
	//
	void DealWithResponse(CURL *curl);
	// 
	void AddBuiltInCookie(CURL *curl);
	//
	void SaveBuiltInCookie(CURL *curl);
	//
	void AddUserCookie(CURL *curl);
private:  
    bool m_bDebug;  
	bool m_bVerifyCert;
	bool m_bFollowRedirect;
	bool m_bTLS;
	int m_iRetryCount;
	std::string m_strProxy;
	std::string m_strProxyUserPwd;
	unsigned long m_ulProxyAuth;
	std::string m_strUserAgent;

	CURL *m_curl;
	std::string m_strDebug;
	std::string m_strLastUrl;
	std::string m_strRedirectUrl;
	double m_fTotalTime;
	long m_nStatusCode;
	std::string m_strIp;
	long m_nPort;

	typedef std::vector<std::string> BuiltInCookieArray;
	typedef BuiltInCookieArray::iterator BuiltInCookieArrayIter;
	BuiltInCookieArray m_aryBuiltInCookie;

	typedef std::vector<UserCookie> UserCookieArray;
	typedef UserCookieArray::iterator UserCookieArrayIter;
	UserCookieArray m_aryUserCookie;

	std::string addCookie;
private:
	static CURLSH *m_curlsh;
};  

class CHttpClientEx : public CHttpClient
{
public:  
	CHttpClientEx(void);  
	virtual ~CHttpClientEx(void);  
public:
	//
	virtual int DoProtoLogin(const std::string &strUrl, const std::string &strUser, const std::string &strPass);
protected:
	
private:
};