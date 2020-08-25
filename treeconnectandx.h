#pragma once
#include "sessionsetupandx.h"

#pragma pack(push, 1)

typedef struct REQ_TREE_CONNECT_ANDX {
	BYTE WordCount;
	ANDX Andx;
	WORD Flags;
	WORD PasswordLength;
	WORD Bytecount;
	union {
		struct {
			BYTE Password;
			BYTE Buffer[1];
		};
		BYTE Bytes[2];
	};
}*PREQ_TREE_CONNECT_ANDX;

#pragma pack(pop)
