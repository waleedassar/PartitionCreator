#include "stdafx.h"
#include "windows.h"
#include "ntsecapi.h"
#include "sddl.h"


bool InitLsaString(
  PLSA_UNICODE_STRING pLsaString,
  LPCWSTR pwszString
)
{
  DWORD dwLen = 0;

  if (NULL == pLsaString)
      return FALSE;

  if (NULL != pwszString) 
  {
      dwLen = wcslen(pwszString);
      if (dwLen > 0x7ffe)   // String is too large
          return FALSE;
  }

  // Store the string.
  pLsaString->Buffer = (WCHAR *)pwszString;
  pLsaString->Length =  (USHORT)dwLen * sizeof(WCHAR);
  pLsaString->MaximumLength= (USHORT)(dwLen+1) * sizeof(WCHAR);

  return TRUE;
}


PSID GetSid(LSA_HANDLE LsaPol)
{
	LSA_UNICODE_STRING lucName={0};

	#define MAX_USER_LENGTH 0x100
	unsigned long LenXX = MAX_USER_LENGTH + 1;
	wchar_t BufferUserName[MAX_USER_LENGTH+1]={0};
	
	GetUserName(BufferUserName,&LenXX);
	wprintf(L"User: %s\r\n",BufferUserName);

	//LenXX = wcslen(BufferUserName)*2;
	//lucName.Length = LenXX;
	//lucName.MaximumLength = LenXX + 2;
	//lucName.Buffer = BufferUserName;
	InitLsaString(&lucName, BufferUserName);

	PLSA_TRANSLATED_SID ltsTranslatedSID;
	PLSA_REFERENCED_DOMAIN_LIST lrdlDomainList;


	NTSTATUS ntsResult = LsaLookupNames(
     LsaPol,
     1,
     &lucName,
     &lrdlDomainList,
     &ltsTranslatedSID);


	if(ntsResult != 0)
	{
		printf("LsaLookupNames, err: %X\r\n",ntsResult);
		return 0;
	}


	_SID* DomainSid = (_SID*) lrdlDomainList->Domains[ltsTranslatedSID->DomainIndex].Sid;

	//printf("Revision: %X\r\n",DomainSid->Revision);
	//printf("SubAuthorityCount: %X\r\n",DomainSid->SubAuthorityCount);

	
	wchar_t* pStrDomainSid = 0;
	ConvertSidToStringSid(DomainSid,&pStrDomainSid);
	wprintf(L"Domain Sid: %s\r\n",pStrDomainSid);

	
	unsigned long long rid = ltsTranslatedSID->RelativeId;
	printf("RID: %I64X\r\n",rid);

	wchar_t BufferRID[0x200]={0};
	_ultow(rid,BufferRID,10);
	//wprintf(L"%s\r\n",BufferRID);

	unsigned long Len1 = wcslen(pStrDomainSid)*2;
	unsigned long Len2 = wcslen(BufferRID)*2;

	wchar_t* pSid = (wchar_t*)LocalAlloc(LMEM_ZEROINIT,Len1+Len2+2+2);
	wcscat(pSid,pStrDomainSid);
	wcscat(pSid,L"-");
	wcscat(pSid,BufferRID);

	wprintf(L"Sid: %s\r\n",pSid);

	LocalFree(pStrDomainSid);

	LsaFreeMemory(lrdlDomainList);
	LsaFreeMemory(ltsTranslatedSID);

	PSID Final;
	ConvertStringSidToSid(pSid,&Final);
	LocalFree(pSid);
	return Final;
}


int Policy(LSA_HANDLE* ppLsaPolicy)
{
	wchar_t MachineName[MAX_COMPUTERNAME_LENGTH+1]={0};
	unsigned long Length = MAX_COMPUTERNAME_LENGTH+1;
	if(!GetComputerName(MachineName,&Length))
	{
		printf("GetComputerName failed, err: %X\r\n",GetLastError());
		return -1;
	}

	wprintf(L"Machine: %s\r\n",MachineName);

	unsigned long MachLen = wcslen(MachineName)*2;

	LSA_UNICODE_STRING lusSystemName={0};
	lusSystemName.Length = MachLen;
	lusSystemName.MaximumLength = MachLen + 2;
	lusSystemName.Buffer = MachineName;


	LSA_OBJECT_ATTRIBUTES ObjectAttributes={0};
	LSA_HANDLE lsahPolicyHandle = 0;
	NTSTATUS ntsResult = LsaOpenPolicy(&lusSystemName,&ObjectAttributes,POLICY_ALL_ACCESS,&lsahPolicyHandle);

	if (ntsResult != 0)
	{
		printf("LsaOpenPolicy Failed, err: %X\r\n",GetLastError());
		return -2;
	}

	if(ppLsaPolicy) *ppLsaPolicy = lsahPolicyHandle;
	return 0;
}



BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet=FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}


bool Acquire(wchar_t* pPrivName)
{
	HANDLE hProcess=GetCurrentProcess();
	HANDLE hToken;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		BOOL b = SetPrivilege(hToken, pPrivName, TRUE);
		CloseHandle(hToken);
		return b;
	}
	return false;
}



bool AddAndEnablePrivilege(wchar_t* pPrivName)
{
	LSA_HANDLE LsaPolicy = 0;
	int ret = Policy(&LsaPolicy);
	if(ret < 0)
	{
		return false;
	}
	
	PSID MySid = GetSid(LsaPolicy);
	if(!MySid)
	{
		LsaClose(LsaPolicy);
		return false;
	}

	LSA_UNICODE_STRING lucPrivilege = {0};
	bool bInit = InitLsaString(&lucPrivilege,pPrivName);
	if(!bInit)
	{
		LocalFree(MySid);
		LsaClose(LsaPolicy);
		return false;
	}
	

	NTSTATUS St = LsaAddAccountRights(LsaPolicy,MySid,&lucPrivilege,1);
	//printf("St: %I64X\r\n",St);
	if(St)
	{
		LocalFree(MySid);
		LsaClose(LsaPolicy);
		return false;
	}

	bool bAc = Acquire(pPrivName);
	if(!bAc)
	{
		//printf("Please re-login this account and try again\r\n");
		LocalFree(MySid);
		LsaClose(LsaPolicy);
		return false;
	}
	LocalFree(MySid);
	LsaClose(LsaPolicy);
	return true;
}