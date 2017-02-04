#pragma once


#define MAX_STACK_DEPTH 32
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)
#define NT_WARNING(Status) ((ULONG)(Status) >> 30 == 2)
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION {
	PCHAR SymbolicBackTrace;        // Not filled in
	ULONG TraceCount;
	USHORT Index;
	USHORT Depth;
	PVOID BackTrace[MAX_STACK_DEPTH];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES {
	ULONG CommittedMemory;
	ULONG ReservedMemory;
	ULONG NumberOfBackTraceLookups;
	ULONG NumberOfBackTraces;
	RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;


typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


typedef struct _RTL_HEAP_ENTRY {
	SIZE_T Size;
	USHORT Flags;
	USHORT AllocatorBackTraceIndex;
	union {
		struct {
			SIZE_T Settable;
			ULONG Tag;
		} s1;   // All other heap entries
		struct {
			SIZE_T CommittedSize;
			PVOID FirstBlock;
		} s2;   // RTL_SEGMENT
	} u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY               (USHORT)0x0001
#define RTL_HEAP_SEGMENT            (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE     (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1     (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2     (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3     (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS     (USHORT)0x00E0
#define RTL_HEAP_UNCOMMITTED_RANGE  (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY    (USHORT)0x0200

typedef struct _RTL_HEAP_TAG {
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION {
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[5];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS {
	ULONG NumberOfHeaps;
	RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;



typedef struct _RTL_PROCESS_LOCK_INFORMATION {
	PVOID Address;
	USHORT Type;
	USHORT CreatorBackTraceIndex;

	HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
	LONG LockCount;
	ULONG ContentionCount;
	ULONG EntryCount;

	//
	// The following fields are only valid for Type == RTL_CRITSECT_TYPE
	//

	LONG RecursionCount;

	//
	// The following fields are only valid for Type == RTL_RESOURCE_TYPE
	//

	ULONG NumberOfWaitingShared;
	ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;


typedef struct _RTL_PROCESS_LOCKS {
	ULONG NumberOfLocks;
	RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;



typedef struct _RTL_DEBUG_INFORMATION {
	HANDLE SectionHandleClient;
	PVOID ViewBaseClient;
	PVOID ViewBaseTarget;
	ULONG_PTR ViewBaseDelta;
	HANDLE EventPairClient;
	HANDLE EventPairTarget;
	HANDLE TargetProcessId;
	HANDLE TargetThreadHandle;
	ULONG Flags;
	SIZE_T OffsetFree;
	SIZE_T CommitSize;
	SIZE_T ViewSize;
	PRTL_PROCESS_MODULES Modules;
	PRTL_PROCESS_BACKTRACES BackTraces;
	PRTL_PROCESS_HEAPS Heaps;
	PRTL_PROCESS_LOCKS Locks;
	PVOID SpecificHeap;
	HANDLE TargetProcessHandle;
	PVOID Reserved[6];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;


/* RtlQueryProcessDebugInformation.DebugInfoClassMask constants */
#define RTL_QUERY_PROCESS_MODULES       0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES    0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY  0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS     0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES  0x00000010
#define RTL_QUERY_PROCESS_LOCKS         0x00000020
#define RTL_QUERY_PROCESS_MODULES32     0x00000040
#define RTL_QUERY_PROCESS_NONINVASIVE   0x80000000



typedef PRTL_DEBUG_INFORMATION(*RtlCreateQueryDebugBuffer_t)(IN ULONG  Size, IN BOOLEAN  EventPair);
typedef NTSTATUS(*RtlQueryProcessDebugInformation_t)(IN ULONG  ProcessId, IN ULONG  DebugInfoClassMask, IN OUT PRTL_DEBUG_INFORMATION  DebugBuffer);
typedef NTSTATUS(*RtlDestroyQueryDebugBuffer_t)(IN PRTL_DEBUG_INFORMATION  DebugBuffer);

