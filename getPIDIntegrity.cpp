#include <windows.h>
#include <stdio.h>
#include <sstream>
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID  (SECURITY_MANDATORY_MEDIUM_RID + 0x100)


void ShowProcessIntegrityLevel(DWORD procId) {
    HANDLE hToken;
    HANDLE hProcess;
    DWORD dwLengthNeeded;
    DWORD dwError = ERROR_SUCCESS;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    LPWSTR pStringSid;
    DWORD dwIntegrityLevel;
    bool bResult;

    //hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procId);
    if (hProcess == NULL) {
        DWORD er = GetLastError();
        printf("\nError: %d", er);
    }
    else if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        dwError = GetLastError();
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
            if (dwError != ERROR_INSUFFICIENT_BUFFER)
            {
                pTIL = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLengthNeeded);
                if (pTIL != NULL)
                {
                    bResult = GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded);
                    if (bResult)
                    {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 0);
                        printf("%ul\n", dwIntegrityLevel);
                        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                        {
                            //Low Integrity
                            printf("Low Integrity Process");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_PLUS_RID)
                        {
                            //Medium Integrity
                            printf("Medium Integrity Process");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_PLUS_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                        {
                            //Medium Plus
                            printf("Medium Plus Integrity Process");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            //High Integrity
                            printf("High Integrity Process");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            //System Integrity
                            printf("System Integrity Process");
                        }
                    }
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, pTIL);
        CloseHandle(hToken);
    }
}

void Helper() {
    printf("-----Remote Process Integrity Chcker Helper-----\n");
    printf("          ex: getPIDIntegrity [PID]");
    exit(0);
}
int main(int argc, char* argv[])
{
    if (argc == 2)
    {
        std::istringstream iss(argv[1]);
        int procId;
        if (iss >> procId) {
            ShowProcessIntegrityLevel(procId);
        }
    }
    else {
        Helper();
    }
    
    return 0;
}
