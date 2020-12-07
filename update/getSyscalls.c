#include <stdio.h>
#include <windows.h>

int main(void)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle("ntdll.dll");
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

    // Invalid file exit
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        return -1;
 
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pExportDirectory)
        return -1;

    PDWORD dwAddress = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions);
    PDWORD dwName    = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames);
    PWORD dwOrdinal = (PWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals);

    unsigned char pBuf[32] = { 0 };
    const unsigned char pSig[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

    printf("SYSCALL    ADDRESS      FUNCTION\n");
    printf("-----------------------------------------\n");

    for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
    {
        memset(&pBuf, 0, 32);
        PVOID pAddr = (PVOID)((LPBYTE)pDosHeader + dwAddress[dwOrdinal[i]]);
        char *szName = (char*)pDosHeader + dwName[i];

        memcpy(&pBuf, pAddr, 32);

        if (!pAddr || !szName)
            break;

        for (int x = 0; x < sizeof(pSig); x++)
        {
            if (pBuf[x] != pSig[x])
                break;
         
            if (x == sizeof(pSig) - 1) {
                printf("0x%02X%02X\t   %p\t%s\n", pBuf[5] pBuf[4], pAddr, szName);
            }
        }
    }
}