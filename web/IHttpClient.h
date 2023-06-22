#pragma once

#ifndef HTTPCLIENT_SELF_INCLUDE
#ifndef HTTPCLIENT_NOLIB
#pragma comment(lib, "../libs/HttpClient.lib")
#endif
#endif

#define HTTPCLIENT_API 

#define HC_IS_SUCCESS(ret) ((ret) == 0)

#include <string>

class IHttpClient abstract
{
public:  
	virtual ~IHttpClient(){};

public:
	// url for imap: imap[s]://host[:port]
	// url for pop3: pop3[s]://host[:port]
	// return 0 if login success, 67 if login failed
	virtual int DoProtoLogin(const std::string &strUrl, const std::string &strUser, const std::string &strPass) = 0;

public:
	// these functions does not reuse curl handles
	virtual int DoGetStringByPost(const std::string &strUrl, const std::string &strPostData, std::string &strResponse) = 0;
	// may need to use custom method in WebDAV protocol
	virtual int DoGetStringByPostEx(
		const std::string &strUrl, 
		const std::string &strPostData, 
		std::string &strResponse, 
		const char *pszReferer, 
		const char *pszContentType,
		const char *pszMethod) = 0;
	virtual int DoGetStringByGet(const std::string &strUrl, std::string &strResponse,bool bSaveHeader=false) = 0;
	//virtual int DoGetStringByGetExEx(const std::string &strUrl,std::string &strResponse, const char *pszCookie)=0;
	virtual int DoGetStringByGetEx(const std::string &strUrl, std::string &strResponse, const char *pszReferer,bool bSaveHeader=false) = 0;
	virtual int DoGetFileByPost(const std::string &strUrl, const std::string &strPostData, const std::wstring &strFile) = 0;
	virtual int DoGetFileByPostEx(
		const std::string &strUrl, 
		const std::string &strPostData, 
		const std::wstring &strFile, 
		const char *pszReferer, 
		const char *pszContentType,
		const char *pszMethod) = 0;
	virtual int DoGetFileByGet(const std::string &strUrl, const std::wstring &strFile) = 0;
	virtual int DoGetFileByGetEx(const std::string &strUrl, const std::wstring &strFile, const char *pszReferer) = 0;
	virtual bool DoPutFileToServer(const std::string &strUrl,const std::string &file)=0;

	virtual	std::string GetCookieString()=0;

	virtual	void	SetCookieString(const std::string cookie)=0;
public:
	// 下面这些设置之后会一直采用, 
	//
	virtual void SetDebug(bool bDebug) = 0; 
	// default 1
	virtual void SetRetryCount(int iCount) = 0;
	// called before get or post
	virtual void SetOptVerifyCert(bool bVerifyCert) = 0;
	// 
	virtual void SetOptFollowRedirect(bool bFollowRedirect) = 0;
	// set ssl version
	virtual void SetOptSSLByTLS(bool bTLS) = 0;
	// socks5h://host:port
	// http://host:port
	virtual void SetOptProxy(const char *p) = 0;
	// user:pass
	virtual void SetOptProxyUserPwd(const char *p) = 0;
	//
	virtual void SetOptProxyAuth(unsigned long auth) = 0;
	//
	virtual void SetOptUserAgent(const char *p) = 0;

public: 
	//
	virtual void AddUserCookie(const std::string &strName, const std::string strValue, const std::string &strPath, const std::string &strDomain, bool bHttpOnly, bool bSecure, unsigned long expires) = 0;
	//
	virtual void EncodeURI(std::string &str) = 0;
	//
	virtual void DecodeURI(std::string &str) = 0;
	//
	virtual void AppendPlain(std::string &str, const char *p) = 0;
	//
	virtual void AppendPlain(std::string &str, const std::string &s) = 0;
	//
	virtual void AppendEscaped(std::string &str, const std::string &s) = 0;
	//
	virtual void AppendEscaped(std::string &str, const char *p, int len) = 0;
	//
	virtual void AppendKeyValue(std::string &str, const std::string &strKey, const std::string &strValue, bool bStartWithAnd = true) = 0;
	//
	virtual void GetLastUrl(std::string &str) = 0;
	//
	virtual void GetRedirectUrl(std::string &str) = 0;
	//
	virtual void GetErrorString(std::string &str, int res) = 0;
	//
	virtual double GetTotalTime() = 0;

	virtual long GetStatusCode() = 0;

	virtual	std::string GetRemoteIp() = 0;

	virtual long GetRemotePort() = 0;
};

// these functions are exported
HTTPCLIENT_API bool __stdcall InitHttpClient(); // must be called once at app start
HTTPCLIENT_API void __stdcall UnInitHttpClient(); // called before app exit
HTTPCLIENT_API IHttpClient* __stdcall CreateHttpClient();
HTTPCLIENT_API void __stdcall DestroyHttpClient(IHttpClient *pHttpClient); // pHttpClient can be null

// these functions is going to be loaded dynamically(the module lies in another directory)
typedef HTTPCLIENT_API bool (__stdcall *PF_InitHttpClient)();
typedef HTTPCLIENT_API void (__stdcall *PF_UnInitHttpClient)();

#define MNewHttpClient(phcOld, phcNew) {if (phcOld != NULL) {phcNew = phcOld;} else {phcNew = CreateHttpClient();}}
#define MHttpClientSetProxy(phcOld, phcNew, strProxy, strProxyUserPwd) {if (phcOld != phcNew) {phcNew->SetOptProxy(strProxy.c_str()); phcNew->SetOptProxyUserPwd(strProxyUserPwd.c_str());}}
#define MDeleteHttpClient(phcOld, phcNew) {if (phcOld != phcNew) {DestroyHttpClient(phcNew);}}