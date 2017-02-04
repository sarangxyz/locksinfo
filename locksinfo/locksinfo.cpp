// rtldbg1.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include "DebugQuery.h"
#include <sstream>
#include <tchar.h>
#include <TlHelp32.h>
#include <vector>
#include <winnt.h>

//---------------------------------------------------------------------------------------------------------------------------
static void PrintHelp()
{
    _tprintf(L"usage: locksinfo <pid>\n");
}

//---------------------------------------------------------------------------------------------------------------------------
static void PrintAbout()
{
    _tprintf(L"\na handy utility to list locks acquired in a process\n");
    _tprintf(L"author: Sarang Baheti, source: https://github.com/angeleno/locksinfo \n\n");
}


//---------------------------------------------------------------------------------------------------------------------------
static bool wchar2long_ss(const WCHAR* str, DWORD* out)
{
    std::wstringstream buffer;
    buffer << str;
    buffer >> (*out);
    return !buffer.fail();
}


//---------------------------------------------------------------------------------------------------------------------------
static bool GetProcName(DWORD aPid, std::wstring* out)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    std::wstring procName;
    for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo))
    {
        if (aPid == processInfo.th32ProcessID)
        {
            CloseHandle(processesSnapshot);
            procName = std::wstring(processInfo.szExeFile);
            break;
        }
    }
    CloseHandle(processesSnapshot);

    *out = procName;
    return !procName.empty();
}

//---------------------------------------------------------------------------------------------------------------------------
class LockInfo
{
    PVOID _address;
    HANDLE _owningThd;
    HANDLE _lockingSem;
    int _contentionCount;
    long _lockCountRaw;
    int _type;
    std::vector<PVOID> _creationTraceback;

public:
    LockInfo(HANDLE hProc, PRTL_DEBUG_INFORMATION buffer, size_t idx)
    {
        const RTL_PROCESS_LOCK_INFORMATION& info = buffer->Locks->Locks[idx];

        _address = info.Address;
        _owningThd = info.OwningThread;
        _contentionCount = info.ContentionCount;
        _lockCountRaw = info.LockCount;
        _type = info.Type;
        _lockingSem = NULL;

        //	CS is from other process' memory- do a process memory read
        //	else this will lead to access violation
        //
        RTL_CRITICAL_SECTION _cs;
        size_t numBytesRead = 0;
        BOOL result = ReadProcessMemory(hProc, _address, &_cs, sizeof(_cs), &numBytesRead);
        if (result)
        {
            _owningThd = _cs.OwningThread;
            _lockingSem = _cs.LockSemaphore;
        }

        //	in case buffer has traceback info, leap of faith really
        if (buffer->BackTraces != nullptr && buffer->BackTraces->BackTraces != nullptr)
        {
            const RTL_PROCESS_BACKTRACE_INFORMATION& tb = buffer->BackTraces->BackTraces[info.CreatorBackTraceIndex];
            for (int idx = 0; idx < MAX_STACK_DEPTH; ++idx)
            {
                if (tb.BackTrace[idx] == nullptr)
                    break;
                else
                    _creationTraceback.push_back(tb.BackTrace[idx]);
            }
        }
    }

    PVOID address() const
    {
        return _address;
    }

    int type() const
    {
        return _type;
    }

    HANDLE owningThread() const
    {
        return _owningThd;
    }

    int contentionCount() const
    {
        return _contentionCount;
    }

    long lockCountRaw() const
    {
        //	https://msdn.microsoft.com/en-us/library/ff541979(v=vs.85).aspx
        //	rules:
        //	1) 0th bit shows lock status
        //	2) 1st bit shows whether thread has been woken for this
        //	3) remaining bits are 1s complement for #threads waiting for this lock
        //
        return _lockCountRaw;
    }

    bool isLocked() const
    {
        return (_lockCountRaw & 0x1) == 0;
    }

    bool hasWokenThreads() const
    {
        return ((_lockCountRaw & 0x2) >> 1 == 0);
    }

    int numThreadsWaiting() const
    {
        return (-1 - _lockCountRaw) >> 2;
    }

    bool hasCreationTraceback() const
    {
        return !_creationTraceback.empty();
    }

    std::vector<PVOID> creationTraceback() const
    {
        return _creationTraceback;
    }

    bool hasLockingSemaphore() const
    {
        return _lockingSem;
    }

    HANDLE lockingSemaphore() const
    {
        return _lockingSem;
    }
};

//---------------------------------------------------------------------------------------------------------------------------
static void printLockInfo(size_t idx, const LockInfo& lockInfo)
{
    _tprintf(L"\n#%zd Lock at address-   0x%p\n", idx, lockInfo.address());
    _tprintf(L"Type:              %d\n", lockInfo.type());
    _tprintf(L"OwningThread:      %d\n", lockInfo.owningThread());
    _tprintf(L"LockingSemaphore:  0x%p\n", lockInfo.lockingSemaphore());
    _tprintf(L"ContentionCount:   %lu\n", lockInfo.contentionCount());
    _tprintf(L"LockCountRaw:      %ld\n", lockInfo.lockCountRaw());
    _tprintf(L"  LockStatus:      %ls\n", (lockInfo.isLocked() ? L"locked" : L"not-locked"));
    _tprintf(L"  AnyThreadsWoken: %ls\n", (lockInfo.hasWokenThreads() ? L"yes" : L"no"));
    _tprintf(L"  #ThreadsWaiting: %d\n", lockInfo.numThreadsWaiting());

    if (lockInfo.hasCreationTraceback())
    {
        _tprintf(L"\nCreation traceback:\n");
        const std::vector<PVOID>& creationTB = lockInfo.creationTraceback();
        for (int idx = 0; idx < creationTB.size(); ++idx)
            _tprintf(L"[%2d] %-12p\n", idx, creationTB[idx]);
    }
}

//---------------------------------------------------------------------------------------------------------------------------
int wmain(int argc, WCHAR* argv[])
{
    PrintAbout();
    if (argc != 2)
    {
        PrintHelp();
        return 1;
    }

    DWORD pid = 0;
    if (!wchar2long_ss(argv[1], &pid))
    {
        _tprintf(L"error parsing- %ls to int\n", argv[1]);
        return 1;
    }

    std::wstring procName;
    GetProcName(pid, &procName);


    HMODULE hMod = GetModuleHandle(L"ntdll.dll");
    RtlCreateQueryDebugBuffer_t pfnRtlCreateQueryDebugBuffer = (RtlCreateQueryDebugBuffer_t)GetProcAddress(hMod, "RtlCreateQueryDebugBuffer");
    RtlQueryProcessDebugInformation_t pfnRtlQueryProcessDebugInformation = (RtlQueryProcessDebugInformation_t)GetProcAddress(hMod, "RtlQueryProcessDebugInformation");
    RtlDestroyQueryDebugBuffer_t pfnRtlDestroyQueryDebugBuffer = (RtlDestroyQueryDebugBuffer_t)GetProcAddress(hMod, "RtlDestroyQueryDebugBuffer");

    std::vector<LockInfo> lockInfoVec;

    HANDLE currProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (currProc != NULL && currProc != INVALID_HANDLE_VALUE)
    {
        PRTL_DEBUG_INFORMATION buffer = pfnRtlCreateQueryDebugBuffer(0, 0);
        if (buffer != NULL)
        {
            NTSTATUS status = pfnRtlQueryProcessDebugInformation(pid, RTL_QUERY_PROCESS_LOCKS | RTL_QUERY_PROCESS_BACKTRACES, buffer);
            if (NT_SUCCESS(status))
            {
                lockInfoVec.reserve(buffer->Locks->NumberOfLocks);
                for (ULONG idx = 0; idx < buffer->Locks->NumberOfLocks; ++idx)
                    lockInfoVec.emplace_back(currProc, buffer, idx);
            }
            else
            {
                _tprintf(L"Failed to query lock information for process: %d, %ls\n", pid, procName.c_str());
            }
            status = pfnRtlDestroyQueryDebugBuffer(buffer);
            buffer = nullptr;
        }
        CloseHandle(currProc);

        if (!lockInfoVec.empty())
        {
            _tprintf(L"Locks information for process- %d, %ls\n", pid, procName.c_str());
            _tprintf(L"Found %zd locks\n", lockInfoVec.size());

            std::vector<LockInfo> acquiredLocks;
            std::vector<LockInfo> unLockedLocks;


            for (const LockInfo& lk : lockInfoVec)
            {
                if (lk.isLocked() && lk.owningThread() != NULL)
                    acquiredLocks.push_back(lk);
                else
                    unLockedLocks.push_back(lk);
            }

            if (!acquiredLocks.empty())
            {
                _tprintf(L"\nPrinting %zu acquired locks\n", acquiredLocks.size());
                _tprintf(L"------------------------------------------------------------------------\n");
                for (size_t idx = 0; idx < acquiredLocks.size(); ++idx)
                    printLockInfo(idx, acquiredLocks[idx]);
            }

            bool extraDbg = false;
            if (extraDbg && !unLockedLocks.empty())
            {
                _tprintf(L"\n\nPrinting %zu free locks\n", unLockedLocks.size());
                _tprintf(L"------------------------------------------------------------------------\n");
                for (size_t idx = 0; idx < unLockedLocks.size(); ++idx)
                    printLockInfo(idx, unLockedLocks[idx]);
            }
        }
    }
    else
    {
        _tprintf(L"couldn't open process (%ls) for introspection\n", argv[1]);
        return 1;
    }

    return 0;
}

