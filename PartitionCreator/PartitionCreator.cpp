#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "Shlobj.h"
#include "Header.h"



fNtCreatePartition NtCreatePartition = 0;
fNtManagePartition NtManagePartition = 0;



void Resolve()
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	NtCreatePartition = (fNtCreatePartition)GetProcAddress(hNtdll,"NtCreatePartition");
	NtManagePartition = (fNtManagePartition)GetProcAddress(hNtdll,"NtManagePartition");
	if( (!NtCreatePartition)||(!NtManagePartition)  )
	{
		printf("OS not supported\r\n");
		ExitProcess(-1);
	}
}


HANDLE CreateUnnamedPartition()
{
	HANDLE hParentPartition = (HANDLE)0; //-1 Current Partition, -2 System Partition
	HANDLE hNewPartition = 0; 
	ulonglong DesiredAccess = 3;//0,1,2,3 ( [+0x01c] ValidAccessMask  : 0x1f0003 )





	_OBJECT_ATTRIBUTES ObjAttr={0};
	ObjAttr.Length = sizeof(ObjAttr);
	ObjAttr.Attributes = OBJ_CASE_INSENSITIVE;

	int ret = NtCreatePartition(hParentPartition,(ulonglong)(&hNewPartition),DesiredAccess,(ulonglong)(&ObjAttr));
	printf("NtCreatePartition, ret: %X, hNewPartition: %I64X\r\n",ret,hNewPartition);

	if(ret >= 0)
	{
		return hNewPartition;
	}
	return 0;
}


HANDLE CreateNamedPartition()
{
	HANDLE hParentPartition = (HANDLE)0; //-1 Current Partition, -2 System Partition
	HANDLE hNewPartition = 0; 
	ulonglong DesiredAccess = 3;//0,1,2,3 ( [+0x01c] ValidAccessMask  : 0x1f0003 )

	wchar_t* PartName = L"\\RPC Control\\walied";
	_UNICODE_STRING UniStr={0};
	UniStr.Length = wcslen(PartName) * 2;
	UniStr.MaxLength = UniStr.MaxLength + 2;
	UniStr.Buffer = PartName;



	_OBJECT_ATTRIBUTES ObjAttr={0};
	ObjAttr.Length = sizeof(ObjAttr);
	ObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
	ObjAttr.ObjectName = &UniStr;

	int ret = NtCreatePartition(hParentPartition,(ulonglong)(&hNewPartition),DesiredAccess,(ulonglong)(&ObjAttr));
	printf("NtCreatePartition, ret: %X, hNewPartition: %I64X\r\n",ret,hNewPartition);
	if(ret >= 0)
	{
		wprintf(L"%s created successfully\r\n",PartName);
		return hNewPartition;
	}
	return 0;
}

HANDLE CreateJob()
{
	wchar_t* JobName = L"\\RPC Control\\waliedj";
	_UNICODE_STRING UniStr={0};
	UniStr.Length = wcslen(JobName) * 2;
	UniStr.MaxLength = UniStr.MaxLength + 2;
	UniStr.Buffer = JobName;



	_OBJECT_ATTRIBUTES ObjAttr={0};
	ObjAttr.Length = sizeof(ObjAttr);
	ObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
	ObjAttr.ObjectName = &UniStr;

	HANDLE hJob = 0;
	int ret = ZwCreateJobObject(&hJob,GENERIC_ALL,&ObjAttr);
	printf("ZwCreateJobObject, ret: %X\r\n",ret);
	if(ret >= 0)
	{
		wprintf(L"Job: %s created successfully\r\n",JobName);
		return hJob;
	}
	return 0;
}


ulong GetCurrentPartitionId()
{
	_PARTITION_INFO_USER* pInfo = (_PARTITION_INFO_USER*)LocalAlloc(LMEM_ZEROINIT,sizeof(_PARTITION_INFO_USER));
	if(pInfo)
	{
		pInfo->Flags = 0;
		pInfo->Node = -1;
		pInfo->Flags2 = -1;


	

		int ret = NtManagePartition( (HANDLE)-1 /* Current */,
									0,
									0x0 /* Class */,
									(ulonglong)pInfo,
									0xF0);
		printf("NtManagePartition, ret: %X\r\n",ret);
		if(ret >= 0)
		{
			return pInfo->PartitionId;
		}
		LocalFree(pInfo);
		return ret;
	}
	return -1;
}


ulong GetPartitionId(HANDLE hPartition)
{
	_PARTITION_INFO_USER* pInfo = (_PARTITION_INFO_USER*)LocalAlloc(LMEM_ZEROINIT,sizeof(_PARTITION_INFO_USER));
	if(pInfo)
	{
		pInfo->Flags = 0;
		pInfo->Node = -1;
		pInfo->Flags2 = -1;


	

		int ret = NtManagePartition(hPartition,
									0,
									0x0 /* Class */,
									(ulonglong)pInfo,
									0xF0);
		printf("NtManagePartition, ret: %X\r\n",ret);
		if(ret >= 0)
		{
			return pInfo->PartitionId;
		}
		LocalFree(pInfo);
		return ret;
	}
	return -1;
}

//
//0x200 ==> One page
int PullMemoryFromSystemPartition(HANDLE hDstPartition,ulonglong NumberOfBits)
{
	_PARTITION_MOVE_MEMORY* pMoveMem = (_PARTITION_MOVE_MEMORY*)LocalAlloc(LMEM_ZEROINIT,sizeof(_PARTITION_MOVE_MEMORY));
	if(pMoveMem)
	{
		pMoveMem->AmountToMove = NumberOfBits;//Number Of Pages
		pMoveMem->Flags = 1;
		pMoveMem->Node = -1;//current node



	
		HANDLE hSrcPartition = (HANDLE)-2;/* -1 Current, -2 System */

				

		int ret = NtManagePartition( hDstPartition /* Dst */,
									hSrcPartition /* Src */,
									0x1,
									(ulonglong)pMoveMem,
									0x10);
		printf("NtManagePartition, ret: %X\r\n",ret);
		LocalFree(pMoveMem);
		return ret;
	}
	return -1;
}




int _tmain(int argc, _TCHAR* argv[])
{

	Resolve();
	//------------------

	wchar_t* pPrivName = 0;
	bool bAcc = false;


	bool bLockMemAcquired = false;

	pPrivName = L"SeLockMemoryPrivilege";
	bAcc = Acquire(pPrivName);
	if(!bAcc)
	{
		if(IsUserAnAdmin())
		{
			bool bRet = AddAndEnablePrivilege(pPrivName);
			if(!bRet)
			{
				printf("Please re-login\r\n");
				return -1;
			}
		}
		else
		{
			wprintf(L"Can't acquire %s, please run under an admin account\r\n",pPrivName);
			return -1;
		}
	}


	//------------------------
	printf("System Partition Id: %X\r\n",GetPartitionId((HANDLE)-2));
	printf("Current Partition Id: %X\r\n",GetPartitionId((HANDLE)-1));
	//---------------  Unnamed ----------------
	//HANDLE hPartition = CreateUnnamedPartition();



	//---------------- Named -------------------
	HANDLE hPartition = CreateNamedPartition();
	if(hPartition)
	{
		printf("New Partition Id: %X\r\n",GetPartitionId(hPartition));


		int retP = PullMemoryFromSystemPartition(hPartition,0x20000 /* Number Of Pages */);//0x20000 
		if(retP < 0)
		{
			printf("Can't pull memory from system partition\r\n");
		}


		int ret = 0;


		HANDLE hJob = CreateJob();
		if(hJob)
		{

			ret = ZwSetInformationJobObject(hJob,JobMemoryPartition,&hPartition,0x8);
			printf("ZwSetInformationJobObject, ret: %X\r\n",ret);

			if(ret >= 0)
			{

				printf("Now run PartitionClient.exe\r\n");
			}

		}

		Sleep(-1);
		return 0;
	}
}

