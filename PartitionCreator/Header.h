#pragma once


#define ulong unsigned long
#define ulonglong unsigned long long
#define ULONG unsigned long
#define ULONGLONG unsigned long long
#define ushort unsigned short
#define USHORT unsigned short
#define uchar unsigned char
#define UCHAR unsigned char


#define OBJ_PROTECT_CLOSE 		0x00000001
#define OBJ_INHERIT             0x00000002
#define OBJ_AUDIT_OBJECT_CLOSE  0x00000004
#define OBJ_PERMANENT           0x00000010
#define OBJ_EXCLUSIVE           0x00000020
#define OBJ_CASE_INSENSITIVE    0x00000040
#define OBJ_OPENIF              0x00000080
#define OBJ_OPENLINK            0x00000100
#define OBJ_KERNEL_HANDLE       0x00000200
#define OBJ_FORCE_ACCESS_CHECK  0x00000400
#define OBJ_VALID_ATTRIBUTES    0x000007F2
#define OBJ_CREATOR_INFO_MINE   0x00010000

struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaxLength;
	unsigned long Pad;
	wchar_t* Buffer;
};


struct _OBJECT_ATTRIBUTES {
  ULONGLONG           Length;
  HANDLE          RootDirectory;
  _UNICODE_STRING* ObjectName;
  ULONGLONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
};



//-----------------
struct _PARTITION_MOVE_MEMORY
{
	ulonglong AmountToMove;//at 0xC
	ulong Node;//at 0x8
	ulong Flags;//at 0xC
};



struct _PAGE_LIST_PART_X
{
	ulonglong X;
	ulonglong Y;
};


//Size 0xF0
struct _PARTITION_INFO_USER
{
	ulong Flags;
	ulong Node;
	ulong Flags2;
	ulong NumberOfNodesOut;
	ulonglong ResidentAvailablePages;
	ulonglong TotalCommittedPages;
	ulonglong TotalCommitLimit;
	ulonglong PeakCommitment;
	ulonglong FreeLargePageCount;
	ulonglong B;
	ulonglong C;
	ulonglong D;
	ulonglong E;
	_PAGE_LIST_PART_X PageList[8];
	ulonglong TotalCommitLimitMaximum;
	ulonglong MiX;
	ulong PartitionId;
	ulong Pad;
};



typedef int(*fNtCreatePartition)(HANDLE hPartition,ulonglong pOutHandle,ulonglong DesiredAccess,ulonglong pObjAttr);
typedef int(*fNtManagePartition)(HANDLE hPartition,HANDLE hSecondaryPartition,ulonglong InfoClass,ulonglong pInfo,ulonglong InfoLength);







//------------


#define JobMemoryPartition 0x2B

extern "C"
{
	int ZwCreateJobObject( HANDLE* JobHandle,ACCESS_MASK DesiredAccess,_OBJECT_ATTRIBUTES* ObjectAttributes );
	int ZwSetInformationJobObject(HANDLE JobHandle,ulonglong JobObjectInformationClass,  void* JobObjectInformation,ulonglong JobObjectInformationLength);
	int ZwQueryInformationJobObject(HANDLE JobHandle, ulonglong JobObjectInformationClass,  void* JobObjectInformation, ulonglong JobObjectInformationLength,  ulonglong* ReturnLength);
	int ZwTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus);
}






//-----------
bool AddAndEnablePrivilege(wchar_t* pPrivName);
bool Acquire(wchar_t* pPrivName);