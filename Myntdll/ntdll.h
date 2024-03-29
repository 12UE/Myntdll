#pragma once
#ifndef __NTDLL_H__
#define __NTDLL_H__
#pragma region HEAD
#include<Windows.h>
#include<Psapi.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifdef _NTDDK_
#error This head file can not be compiled together with Ntddk.h
#endif
#pragma endregion
#pragma region NTDLL BASE DEFINE
#ifndef NTSTATUS
    typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif // NT_SUCCESS
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif // STATUS_SUCCESS
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif // STATUS_UNSUCCESSFU
#ifndef ASSERT
#ifdef _DEBUG
#define ASSERT(x) assert(x)
#else // _DEBUG
#define ASSERT(x)
#endif // _DEBUG
#endif // ASSERT
#pragma endregion
#pragma region DEFINE
#define EXPORT extern "C" __declspec(dllexport) __forceinline
#define DEVICE_TYPE DWORD
#define FLG_STOP_ON_EXCEPTION            0x0000001L
#define FLG_SHOW_LDR_SNAPS                0x0000002L
#define FLG_DEBUG_INITIAL_COMMAND        0x0000004L
#define FLG_STOP_ON_HUNG_GUI            0x0000008L
#define FLG_HEAP_ENABLE_TAIL_CHECK        0x0000010L
#define FLG_HEAP_ENABLE_FREE_CHECK        0x0000020L
#define FLG_HEAP_VALIDATE_PARAMETERS    0x0000040L
#define FLG_HEAP_VALIDATE_ALL            0x0000080L
#define FLG_POOL_ENABLE_TAIL_CHECK        0x0000100L
#define FLG_POOL_ENABLE_FREE_CHECK        0x0000200L
#define FLG_POOL_ENABLE_TAGGING            0x0000400L
#define FLG_HEAP_ENABLE_TAGGING            0x0000800L
#define FLG_USER_STACK_TRACE_DB            0x0001000L
#define FLG_KERNEL_STACK_TRACE_DB        0x0002000L
#define FLG_MAINTAIN_OBJECT_TYPELIST    0x0004000L
#define FLG_HEAP_ENABLE_TAG_BY_DLL        0x0008000L
#define FLG_IGNORE_DEBUG_PRIV            0x0010000L
#define FLG_ENABLE_CSRDEBUG                0x0020000L
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD    0x0040000L
#define FLG_DISABLE_PAGE_KERNEL_STACKS    0x0080000L
#define FLG_HEAP_ENABLE_CALL_TRACING    0x0100000L
#define FLG_HEAP_DISABLE_COALESCING        0x0200000L
#define FLG_ENABLE_CLOSE_EXCEPTIONS        0x0400000L
#define FLG_ENABLE_EXCEPTION_LOGGING    0x0800000L
#define FLG_ENABLE_DBGPRINT_BUFFERING    0x8000000L
#define PROTECT_FROM_CLOSE    0x1L
#define INHERIT                0x2L
#define FLG_SYSOBJINFO_SINGLE_HANDLE_ENTRY        0x40L
#define FLG_SYSOBJINFO_DEFAULT_SECURITY_QUOTA    0x20L
#define FLG_SYSOBJINFO_PERMANENT                0x10L
#define FLG_SYSOBJINFO_EXCLUSIVE                0x08L
#define FLG_SYSOBJINFO_CREATOR_INFO                0x04L
#define FLG_SYSOBJINFO_KERNEL_MODE                0x02L
#define PERMANENT                         0x10L
#define EXCLUSIVE                         0x20L
#define WSLE_PAGE_READONLY                0x001L
#define WSLE_PAGE_EXECUTE                 0x002L
#define WSLE_PAGE_READWRITE               0x004L
#define WSLE_PAGE_EXECUTE_READ            0x003L
#define WSLE_PAGE_WRITECOPY               0x005L
#define WSLE_PAGE_EXECUTE_READWRITE       0x006L
#define WSLE_PAGE_EXECUTE_WRITECOPY       0x007L
#define WSLE_PAGE_SHARE_COUNT_MASK        0x0E0L
#define WSLE_PAGE_SHAREABLE               0x100L
#define LOCK_VM_IN_WSL                    0x1L
#define LOCK_VM_IN_RAM                    0x2L
#define PC_IDLE                           0x1L
#define PC_NORMAL                         0x2L
#define PC_HIGH                           0x3L
#define PC_REALTIME                       0x4L
#define PC_BELOW_NORMAL                   0x5L
#define PC_ABOVE_NORMAL                   0x6L
#define PDI_MODULES                       0x01L
#define PDI_BACKTRACE                     0x02L
#define PDI_HEAPS                         0x04L
#define PDI_HEAP_TAGS                     0x08L
#define PDI_HEAP_BLOCKS                   0x10L
#define PDI_LOCKS                         0x20L
#define LDRP_STATIC_LINK                  0x000002L
#define LDRP_IMAGE_DLL                    0x000004L
#define LDRP_LOAD_IN_PROGRESS             0x001000L
#define LDRP_UNLOAD_IN_PROGRESS           0x002000L
#define LDRP_ENTRY_PROCESSED              0x004000L
#define LDRP_ENTRY_INSERTED               0x008000L
#define LDRP_CURRENT_LOAD                 0x010000L
#define LDRP_FAILED_BUILTIN_LOAD          0x020000L
#define LDRP_DONT_CALL_FOR_THREADS        0x040000L
#define LDRP_PROCESS_ATTACH_CALLED        0x080000L
#define LDRP_DEBUG_SYMBOLS_LOADED         0x100000L
#define LDRP_IMAGE_NOT_AT_BASE            0x200000L
#define LDRP_WX86_IGNORE_MACHINETYPE      0x400000L
#define LPC_MESSAGE_BASE_SIZE    0x18L
#define FILE_SUPERSEDE                  0x0L
#define FILE_OPEN                       0x1L
#define FILE_CREATE                     0x2L
#define FILE_OPEN_IF                    0x3L
#define FILE_OVERWRITE                  0x4L
#define FILE_OVERWRITE_IF               0x5L
#define FILE_MAXIMUM_DISPOSITION        0x5L
#define FILE_SUPERSEDED                 0x0L
#define FILE_OPENED                     0x1L
#define FILE_CREATED                    0x2L
#define FILE_OVERWRITTEN                0x3L
#define FILE_EXISTS                     0x4L
#define FILE_DOES_NOT_EXIST             0x5L
#define REG_MONITOR_SINGLE_KEY          0x0L
#define REG_MONITOR_SECOND_KEY          0x1L
#define HASH_STRING_ALGORITHM_DEFAULT   0x00000000L
#define HASH_STRING_ALGORITHM_X65599    0x00000001L
#define HASH_STRING_ALGORITHM_INVALID   0xFFFFFFFFL
#define SE_MIN_WELL_KNOWN_PRIVILEGE            0x02L
#define SE_CREATE_TOKEN_PRIVILEGE            0x02L
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE        0x03L
#define SE_LOCK_MEMORY_PRIVILEGE            0x04L
#define SE_INCREASE_QUOTA_PRIVILEGE            0x05L
#define SE_UNSOLICITED_INPUT_PRIVILEGE        0x06L
#define SE_MACHINE_ACCOUNT_PRIVILEGE        0x06L
#define SE_TCB_PRIVILEGE                    0x07L
#define SE_SECURITY_PRIVILEGE                0x08L
#define SE_TAKE_OWNERSHIP_PRIVILEGE            0x09L
#define SE_LOAD_DRIVER_PRIVILEGE            0x0AL
#define SE_SYSTEM_PROFILE_PRIVILEGE            0x0BL
#define SE_SYSTEMTIME_PRIVILEGE                0x0CL
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    0x0DL
#define SE_INC_BASE_PRIORITY_PRIVILEGE        0x0EL
#define SE_CREATE_PAGEFILE_PRIVILEGE        0x0FL
#define SE_CREATE_PERMANENT_PRIVILEGE        0x10L
#define SE_BACKUP_PRIVILEGE                    0x11L
#define SE_RESTORE_PRIVILEGE                0x12L
#define SE_SHUTDOWN_PRIVILEGE                0x13L
#define SE_DEBUG_PRIVILEGE                    0x14L
#define SE_AUDIT_PRIVILEGE                    0x15L
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE        0x16L
#define SE_CHANGE_NOTIFY_PRIVILEGE            0x17L
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        0x18L
#define SE_UNDOCK_PRIVILEGE                    0x19L
#define SE_SYNC_AGENT_PRIVILEGE                0x1AL
#define SE_ENABLE_DELEGATION_PRIVILEGE        0x1BL
#define SE_MANAGE_VOLUME_PRIVILEGE            0x1CL
#define SE_IMPERSONATE_PRIVILEGE            0x1DL
#define SE_CREATE_GLOBAL_PRIVILEGE            0x1EL
#define SE_MAX_WELL_KNOWN_PRIVILEGE            SE_CREATE_GLOBAL_PRIVILEGE
#define OBJ_INHERIT                0x002L
#define OBJ_PERMANENT            0x010L
#define OBJ_EXCLUSIVE            0x020L
#define OBJ_CASE_INSENSITIVE    0x040L
#define OBJ_OPENIF                0x080L
#define OBJ_OPENLINK            0x100L
#define OBJ_KERNEL_HANDLE        0x200L
#define OBJ_FORCE_ACCESS_CHECK    0x400L
#define OBJ_VALID_ATTRIBUTES    0x7F2L

#define DIRECTORY_QUERY                    0x0001L
#define DIRECTORY_TRAVERSE                0x0002L
#define DIRECTORY_CREATE_OBJECT            0x0004L
#define DIRECTORY_CREATE_SUBDIRECTORY    0x0008L
#define DIRECTORY_ALL_ACCESS            (STANDARD_RIGHTS_REQUIRED | 0x000FL)
#define LEVEL_HANDLE_ID            0x74000000L
#define LEVEL_HANDLE_ID_MASK    0xFF000000L
#define LEVEL_HANDLE_INDEX_MASK    0x00FFFFFFL
#define RTL_QUERY_REGISTRY_SUBKEY    0x01L
#define RTL_QUERY_REGISTRY_TOPKEY    0x02L
#define RTL_QUERY_REGISTRY_REQUIRED    0x04L
#define RTL_QUERY_REGISTRY_NOVALUE    0x08L
#define RTL_QUERY_REGISTRY_NOEXPAND    0x10L
#define RTL_QUERY_REGISTRY_DIRECT    0x20L
#define RTL_QUERY_REGISTRY_DELETE    0x40L
#define RTL_REGISTRY_ABSOLUTE    0x00000000L
#define RTL_REGISTRY_SERVICES    0x00000001L
#define RTL_REGISTRY_CONTROL    0x00000002L
#define RTL_REGISTRY_WINDOWS_NT    0x00000003L
#define RTL_REGISTRY_DEVICEMAP    0x00000004L
#define RTL_REGISTRY_USER        0x00000005L
#define RTL_REGISTRY_MAXIMUM    0x00000006L
#define RTL_REGISTRY_HANDLE        0x40000000L
#define RTL_REGISTRY_OPTIONAL    0x80000000L
#define OLD_DOS_VOLID    0x8L
#define FILE_DIRECTORY_FILE                     0x000001L
#define FILE_WRITE_THROUGH                      0x000002L
#define FILE_SEQUENTIAL_ONLY                    0x000004L
#define FILE_NO_INTERMEDIATE_BUFFERING          0x000008L
#define FILE_SYNCHRONOUS_IO_ALERT               0x000010L
#define FILE_SYNCHRONOUS_IO_NONALERT            0x000020L
#define FILE_NON_DIRECTORY_FILE                 0x000040L
#define FILE_CREATE_TREE_CONNECTION             0x000080L
#define FILE_COMPLETE_IF_OPLOCKED               0x000100L
#define FILE_NO_EA_KNOWLEDGE                    0x000200L
#define FILE_OPEN_FOR_RECOVERY                  0x000400L
#define FILE_RANDOM_ACCESS                      0x000800L
#define FILE_DELETE_ON_CLOSE                    0x001000L
#define FILE_OPEN_BY_FILE_ID                    0x002000L
#define FILE_OPEN_FOR_BACKUP_INTENT             0x004000L
#define FILE_NO_COMPRESSION                     0x008000L
#define FILE_OPEN_REQUIRING_OPLOCK              0x010000L
#define FILE_DISALLOW_EXCLUSIVE                 0x020000L
#define FILE_RESERVE_OPFILTER                   0x100000L
#define FILE_OPEN_REPARSE_POINT                 0x200000L
#define FILE_OPEN_NO_RECALL                     0x400000L
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x800000L
#define GDI_HANDLE_BUFFER_SIZE    0x22L
#define MEM_EXECUTE_OPTION_DISABLE   0x01L
#define MEM_EXECUTE_OPTION_ENABLE    0x02L
#define MEM_EXECUTE_OPTION_PERMANENT 0x08L
#define MAX_LPC_DATA 0x130L
#define ALPC_REQUEST            0x2000L | LPC_REQUEST
#define ALPC_CONNECTION_REQUEST 0x2000L | LPC_CONNECTION_REQUEST
#define SYMBOLIC_LINK_QUERY            0x1L
#define SYMBOLIC_LINK_ALL_ACCESS    STANDARD_RIGHTS_REQUIRED | 0x1L
#define EVENT_PAIR_ALL_ACCESS STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE 
#pragma endregion
#pragma region TYPEDEF
    typedef LONG KPRIORITY;
    typedef PVOID PLANGID;
    typedef ULONG_PTR KAFFINITY;
    typedef USHORT RTL_ATOM, * PRTL_ATOM;
    typedef LARGE_INTEGER PHYSICAL_ADDRESS;
#pragma endregion
#pragma region ENUM
    typedef enum _THREADINFOCLASS
    {
        ThreadBasicInformation,
        ThreadTimes,
        ThreadPriority,
        ThreadBasePriority,
        ThreadAffinityMask,
        ThreadImpersonationToken,
        ThreadDescriptorTableEntry,
        ThreadEnableAlignmentFaultFixup,
        ThreadEventPair_Reusable,
        ThreadQuerySetWin32StartAddress,
        ThreadZeroTlsCell,
        ThreadPerformanceCount,
        ThreadAmILastThread,
        ThreadIdealProcessor,
        ThreadPriorityBoost,
        ThreadSetTlsArrayAddress,
        ThreadIsIoPending,
        ThreadHideFromDebugger,
        ThreadBreakOnTermination,
        MaxThreadInfoClass
    } THREADINFOCLASS;
    typedef enum _KPROFILE_SOURCE
    {
        ProfileTime,
        ProfileAlignmentFixup,
        ProfileTotalIssues,
        ProfilePipelineDry,
        ProfileLoadInstructions,
        ProfilePipelineFrozen,
        ProfileBranchInstructions,
        ProfileTotalNonissues,
        ProfileDcacheMisses,
        ProfileIcacheMisses,
        ProfileCacheMisses,
        ProfileBranchMispredictions,
        ProfileStoreInstructions,
        ProfileFpInstructions,
        ProfileIntegerInstructions,
        Profile2Issue,
        Profile3Issue,
        Profile4Issue,
        ProfileSpecialInstructions,
        ProfileTotalCycles,
        ProfileIcacheIssues,
        ProfileDcacheAccesses,
        ProfileMemoryBarrierCycles,
        ProfileLoadLinkedIssues,
        ProfileMaximum
    } KPROFILE_SOURCE;

    typedef enum _KWAIT_REASON
    {
        Executive,
        FreePage,
        PageIn,
        PoolAllocation,
        DelayExecution,
        Suspended,
        UserRequest,
        WrExecutive,
        WrFreePage,
        WrPageIn,
        WrPoolAllocation,
        WrDelayExecution,
        WrSuspended,
        WrUserRequest,
        WrEventPair,
        WrQueue,
        WrLpcReceive,
        WrLpcReply,
        WrVirtualMemory,
        WrPageOut,
        WrRendezvous,
        Spare2,
        Spare3,
        Spare4,
        Spare5,
        Spare6,
        WrKernel,
        MaximumWaitReason
    } KWAIT_REASON;



    typedef enum _THREAD_STATE
    {
        StateInitialized,
        StateReady,
        StateRunning,
        StateStandby,
        StateTerminated,
        StateWait,
        StateTransition,
        StateUnknown
    } THREAD_STATE;

   

    typedef enum _DEBUG_CONTROL_CODE
    {
        DebugGetTraceInformation = 1,
        DebugSetInternalBreakpoint,
        DebugSetSpecialCall,
        DebugClearSpecialCalls,
        DebugQuerySpecialCalls,
        DebugDbgBreakPoint,
        DebugMaximum
    } DEBUG_CONTROL_CODE;

    typedef enum _SYSDBG_COMMAND
    {
        SysDbgQueryModuleInformation = 0,
        SysDbgQueryTraceInformation,
        SysDbgSetTracepoint,
        SysDbgSetSpecialCall,
        SysDbgClearSpecialCalls,
        SysDbgQuerySpecialCalls,
        SysDbgBreakPoint,
        SysDbgQueryVersion,
        SysDbgReadVirtual,
        SysDbgWriteVirtual,
        SysDbgReadPhysical,
        SysDbgWritePhysical,
        SysDbgReadControlSpace,
        SysDbgWriteControlSpace,
        SysDbgReadIoSpace,
        SysDbgWriteIoSpace,
        SysDbgReadMsr,
        SysDbgWriteMsr,
        SysDbgReadBusData,
        SysDbgWriteBusData,
        SysDbgCheckLowMemory,
        SysDbgEnableKernelDebugger,
        SysDbgDisableKernelDebugger,
        SysDbgGetAutoKdEnable,
        SysDbgSetAutoKdEnable,
        SysDbgGetPrintBufferSize,
        SysDbgSetPrintBufferSize,
        SysDbgGetKdUmExceptionEnable,
        SysDbgSetKdUmExceptionEnable,
        SysDbgGetTriageDump,
        SysDbgGetKdBlockEnable,
        SysDbgSetKdBlockEnable,
    } SYSDBG_COMMAND, * PSYSDBG_COMMAND;

    typedef enum _INTERFACE_TYPE
    {
        InterfaceTypeUndefined = -1,
        Internal,
        Isa,
        Eisa,
        MicroChannel,
        TurboChannel,
        PCIBus,
        VMEBus,
        NuBus,
        PCMCIABus,
        CBus,
        MPIBus,
        MPSABus,
        ProcessorInternal,
        InternalPowerBus,
        PNPISABus,
        PNPBus,
        MaximumInterfaceType
    }INTERFACE_TYPE, * PINTERFACE_TYPE;

    typedef enum _BUS_DATA_TYPE
    {
        ConfigurationSpaceUndefined = -1,
        Cmos,
        EisaConfiguration,
        Pos,
        CbusConfiguration,
        PCIConfiguration,
        VMEConfiguration,
        NuBusConfiguration,
        PCMCIAConfiguration,
        MPIConfiguration,
        MPSAConfiguration,
        PNPISAConfiguration,
        SgiInternalConfiguration,
        MaximumBusDataType
    } BUS_DATA_TYPE, * PBUS_DATA_TYPE;

    typedef enum _OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllTypesInformation,
        ObjectHandleInformation
    } OBJECT_INFORMATION_CLASS;

    typedef enum _LPC_TYPE
    {
        LPC_NEW_MESSAGE,
        LPC_REQUEST,
        LPC_REPLY,
        LPC_DATAGRAM,
        LPC_LOST_REPLY,
        LPC_PORT_CLOSED,
        LPC_CLIENT_DIED,
        LPC_EXCEPTION,
        LPC_DEBUG_EVENT,
        LPC_ERROR_EVENT,
        LPC_CONNECTION_REQUEST,
        LPC_CONNECTION_REFUSED,
        LPC_MAXIMUM
    } LPC_TYPE;

    typedef enum _KEY_SET_INFORMATION_CLASS
    {
        KeyLastWriteTimeInformation
    } KEY_SET_INFORMATION_CLASS;

    typedef enum _HARDERROR_RESPONSE_OPTION
    {
        OptionAbortRetryIgnore,
        OptionOk,
        OptionOkCancel,
        OptionRetryCancel,
        OptionYesNo,
        OptionYesNoCancel,
        OptionShutdownSystem
    } HARDERROR_RESPONSE_OPTION, * PHARDERROR_RESPONSE_OPTION;

    typedef enum _HARDERROR_RESPONSE
    {
        ResponseReturnToCaller,
        ResponseNotHandled,
        ResponseAbort,
        ResponseCancel,
        ResponseIgnore,
        ResponseNo,
        ResponseOk,
        ResponseRetry,
        ResponseYes
    } HARDERROR_RESPONSE, * PHARDERROR_RESPONSE;

    typedef enum _ATOM_INFORMATION_CLASS
    {
        AtomBasicInformation,
        AtomListInformation
    } ATOM_INFORMATION_CLASS;

    typedef enum _PORT_INFORMATION_CLASS
    {
        PortBasicInformation
    } PORT_INFORMATION_CLASS;

    typedef enum _EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent
    } EVENT_TYPE;


    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;

    typedef enum _KEY_VALUE_INFORMATION_CLASS
    {
        KeyValueBasicInformation,
        KeyValueFullInformation,
        KeyValuePartialInformation,
        KeyValueFullInformationAlign64,
        KeyValuePartialInformationAlign64,
        MaxKeyValueInfoClass
    } KEY_VALUE_INFORMATION_CLASS;

    typedef enum _KEY_INFORMATION_CLASS
    {
        KeyBasicInformation,
        KeyNodeInformation,
        KeyFullInformation,
        KeyNameInformation,
        KeyCachedInformation,
        KeyFlagsInformation,
        MaxKeyInfoClass
    } KEY_INFORMATION_CLASS;

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        SystemPowerInformationNative,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemAddVerifier,
        SystemSessionProcessesInformation,
        SystemLoadGdiDriverInSystemSpaceInformation,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHanfleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchDogTimerHandler,
        SystemWatchDogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWo64SharedInformationObosolete,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        SystemThreadPriorityClientIdInformation,
        SystemProcessorIdleCycleTimeInformation,
        SystemVerifierCancellationInformation,
        SystemProcessorPowerInformationEx,
        SystemRefTraceInformation,
        SystemSpecialPoolInformation,
        SystemProcessIdInformation,
        SystemErrorPortInformation,
        SystemBootEnvironmentInformation,
        SystemHypervisorInformation,
        SystemVerifierInformationEx,
        SystemTimeZoneInformation,
        SystemImageFileExecutionOptionsInformation,
        SystemCoverageInformation,
        SystemPrefetchPathInformation,
        SystemVerifierFaultsInformation,
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

    typedef enum _SHUTDOWN_ACTION
    {
        ShutdownNoReboot,
        ShutdownReboot,
        ShutdownPowerOff
    } SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

    typedef enum _FILE_INFORMATION_CLASS
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation,
        FileBothDirectoryInformation,
        FileBasicInformation,
        FileStandardInformation,
        FileInternalInformation,
        FileEaInformation,
        FileAccessInformation,
        FileNameInformation,
        FileRenameInformation,
        FileLinkInformation,
        FileNamesInformation,
        FileDispositionInformation,
        FilePositionInformation,
        FileFullEaInformation,
        FileModeInformation,
        FileAlignmentInformation,
        FileAllInformation,
        FileAllocationInformation,
        FileEndOfFileInformation,
        FileAlternateNameInformation,
        FileStreamInformation,
        FilePipeInformation,
        FilePipeLocalInformation,
        FilePipeRemoteInformation,
        FileMailslotQueryInformation,
        FileMailslotSetInformation,
        FileCompressionInformation,
        FileObjectIdInformation,
        FileCompletionInformation,
        FileMoveClusterInformation,
        FileQuotaInformation,
        FileReparsePointInformation,
        FileNetworkOpenInformation,
        FileAttributeTagInformation,
        FileTrackingInformation,
        FileIdBothDirectoryInformation,
        FileIdFullDirectoryInformation,
        FileValidDataLengthInformation,
        FileShortNameInformation,
        FileIoCompletionNotificationInformation,
        FileIoStatusBlockRangeInformation,
        FileIoPriorityHintInformation,
        FileSfioReserveInformation,
        FileSfioVolumeInformation,
        FileHardLinkInformation,
        FileProcessIdsUsingFileInformation,
        FileNormalizedNameInformation,
        FileNetworkPhysicalNameInformation,
        FileIdGlobalTxDirectoryInformation,
        FileIsRemoteDeviceInformation,
        FileAttributeCacheInformation,
        FileNumaNodeInformation,
        FileStandardLinkInformation,
        FileRemoteProtocolInformation,
        FileMaximumInformation
    } FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;


    typedef enum _FSINFOCLASS
    {
        FileFsVolumeInformation = 1,
        FileFsLabelInformation,
        FileFsSizeInformation,
        FileFsDeviceInformation,
        FileFsAttributeInformation,
        FileFsControlInformation,
        FileFsFullSizeInformation,
        FileFsObjectIdInformation,
        FileFsDriverPathInformation,
        FileFsVolumeFlagsInformation,
        FileFsMaximumInformation
    } FS_INFORMATION_CLASS, * PFS_INFORMATION_CLASS;

    typedef enum _PROCESSINFOCLASS
    {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        ProcessDeviceMap,
        ProcessSessionInformation,
        ProcessForegroundInformation,
        ProcessWow64Information,
        ProcessImageFileName,
        ProcessLUIDDeviceMapsEnabled,
        ProcessBreakOnTermination,
        ProcessDebugObjectHandle,
        ProcessDebugFlags,
        ProcessHandleTracing,
        ProcessIoPriority,
        ProcessExecuteFlags,
        ProcessTlsInformation,
        ProcessCookie,
        ProcessImageInformation,
        ProcessCycleTime,
        ProcessPagePriority,
        ProcessInstrumentationCallback,
        ProcessThreadStackAllocation,
        ProcessWorkingSetWatchEx,
        ProcessImageFileNameWin32,
        ProcessImageFileMapping,
        ProcessAffinityUpdateMode,
        ProcessMemoryAllocationMode,
        ProcessGroupInformation,
        ProcessTokenVirtualizationEnabled,
        ProcessConsoleHostProcess,
        ProcessWindowInformation,
        MaxProcessInfoClass
    } PROCESSINFOCLASS;

    typedef enum _MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation,
        MemoryWorkingSetInformation,
        MemoryMappedFilenameInformation,
        MemoryRegionInformation,
        MemoryWorkingSetExInformation
    } MEMORY_INFORMATION_CLASS;

    typedef enum _WAIT_TYPE
    {
        WaitAll,
        WaitAny
    } WAIT_TYPE;

    typedef enum _EVENT_INFORMATION_CLASS
    {
        EventBasicInformation
    } EVENT_INFORMATION_CLASS;

    typedef enum _SECTION_INFORMATION_CLASS
    {
        SectionBasicInformation,
        SectionImageInformation
    } SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

#pragma endregion

#pragma region STRUCT

    typedef struct _STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PCHAR Buffer;
    } STRING, ANSI_STRING, OEM_STRING, * PSTRING, * PANSI_STRING, * PCANSI_STRING, * POEM_STRING;
    typedef const STRING* PCOEM_STRING;

    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;

    typedef struct _CLIENT_ID
    {
        HANDLE  UniqueProcess;
        HANDLE  UniqueThread;
    } CLIENT_ID, * PCLIENT_ID;

    typedef struct _CURDIR
    {
        UNICODE_STRING DosPath;
        HANDLE Handle;
    } CURDIR, * PCURDIR;

    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

    typedef struct _PEB_FREE_BLOCK
    {
        struct _PEB_FREE_BLOCK* Next;
        ULONG Size;
    } PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID      EntryInProgress;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _RTL_DRIVE_LETTER_CURDIR
    {
        USHORT Flags;
        USHORT Length;
        ULONG  TimeStamp;
        STRING DosPath;
    } RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        ULONG MaximumLength;
        ULONG Length;
        ULONG Flags;
        ULONG DebugFlags;
        PVOID ConsoleHandle;
        ULONG ConsoleFlags;
        HANDLE StandardInput;
        HANDLE StandardOutput;
        HANDLE StandardError;
        CURDIR CurrentDirectory;
        UNICODE_STRING DllPath;
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
        PVOID Environment;
        ULONG StartingX;
        ULONG StartingY;
        ULONG CountX;
        ULONG CountY;
        ULONG CountCharsX;
        ULONG CountCharsY;
        ULONG FillAttribute;
        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        UNICODE_STRING WindowTitle;
        UNICODE_STRING DesktopInfo;
        UNICODE_STRING ShellInfo;
        UNICODE_STRING RuntimeData;
        RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef struct _PEB
    {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN SpareBool;
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PVOID FastPebLock;
        PVOID FastPebLockRoutine;
        PVOID FastPebUnlockRoutine;
        ULONG EnvironmentUpdateCount;
        PVOID KernelCallbackTable;
        HANDLE SystemReserved;
        PVOID  AtlThunkSListPtr32;
        PPEB_FREE_BLOCK FreeList;
        ULONG TlsExpansionCounter;
        PVOID TlsBitmap;
        ULONG TlsBitmapBits[2];
        PVOID ReadOnlySharedMemoryBase;
        PVOID ReadOnlySharedMemoryHeap;
        PVOID* ReadOnlyStaticServerData;
        PVOID AnsiCodePageData;
        PVOID OemCodePageData;
        PVOID UnicodeCaseTableData;
        ULONG NumberOfProcessors;
        ULONG NtGlobalFlag;
        LARGE_INTEGER CriticalSectionTimeout;
        ULONG HeapSegmentReserve;
        ULONG HeapSegmentCommit;
        ULONG HeapDeCommitTotalFreeThreshold;
        ULONG HeapDeCommitFreeBlockThreshold;
        ULONG NumberOfHeaps;
        ULONG MaximumNumberOfHeaps;
        PVOID* ProcessHeaps;
        PVOID GdiSharedHandleTable;
        PVOID ProcessStarterHelper;
        PVOID GdiDCAttributeList;
        PVOID LoaderLock;
        ULONG OSMajorVersion;
        ULONG OSMinorVersion;
        USHORT OSBuildNumber;
        USHORT OSCSDVersion;
        ULONG OSPlatformId;
        ULONG ImageSubsystem;
        ULONG ImageSubsystemMajorVersion;
        ULONG ImageSubsystemMinorVersion;
        ULONG ImageProcessAffinityMask;
        ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
    } PEB, * PPEB;

    typedef struct _TEB
    {
        NT_TIB NtTib;
        PVOID  EnvironmentPointer;
        CLIENT_ID ClientId;
        PVOID ActiveRpcHandle;
        PVOID ThreadLocalStoragePointer;
        PPEB ProcessEnvironmentBlock;
        ULONG LastErrorValue;
        ULONG CountOfOwnedCriticalSections;
        PVOID CsrClientThread;
        PVOID Win32ThreadInfo;
    } TEB, * PTEB;

    typedef struct _INITIAL_TEB
    {
        PVOID                StackBase;
        PVOID                StackLimit;
        PVOID                StackCommit;
        PVOID                StackCommitMax;
        PVOID                StackReserved;
    } INITIAL_TEB, * PINITIAL_TEB;

    typedef struct _FILE_NETWORK_OPEN_INFORMATION
    {
        LARGE_INTEGER  CreationTime;
        LARGE_INTEGER  LastAccessTime;
        LARGE_INTEGER  LastWriteTime;
        LARGE_INTEGER  ChangeTime;
        LARGE_INTEGER  AllocationSize;
        LARGE_INTEGER  EndOfFile;
        ULONG  FileAttributes;
    } FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

    typedef struct _IO_STATUS_BLOCK
    {
        union
        {
            NTSTATUS Status;
            PVOID Pointer;
        };
        ULONG_PTR Information;
    } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

    typedef struct _KEY_VALUE_ENTRY
    {
        PUNICODE_STRING ValueName;
        ULONG           DataLength;
        ULONG           DataOffset;
        ULONG           Type;
    } KEY_VALUE_ENTRY, * PKEY_VALUE_ENTRY;


    typedef struct _SYSTEM_PERFORMANCE_INFORMATION
    {
        LARGE_INTEGER IdleProcessTime;
        LARGE_INTEGER IoReadTransferCount;
        LARGE_INTEGER IoWriteTransferCount;
        LARGE_INTEGER IoOtherTransferCount;
        ULONG IoReadOperationCount;
        ULONG IoWriteOperationCount;
        ULONG IoOtherOperationCount;
        ULONG AvailablePages;
        ULONG CommittedPages;
        ULONG CommitLimit;
        ULONG PeakCommitment;
        ULONG PageFaultCount;
        ULONG CopyOnWriteCount;
        ULONG TransitionCount;
        ULONG CacheTransitionCount;
        ULONG DemandZeroCount;
        ULONG PageReadCount;
        ULONG PageReadIoCount;
        ULONG CacheReadCount;
        ULONG CacheIoCount;
        ULONG DirtyPagesWriteCount;
        ULONG DirtyWriteIoCount;
        ULONG MappedPagesWriteCount;
        ULONG MappedWriteIoCount;
        ULONG PagedPoolPages;
        ULONG NonPagedPoolPages;
        ULONG PagedPoolAllocs;
        ULONG PagedPoolFrees;
        ULONG NonPagedPoolAllocs;
        ULONG NonPagedPoolFrees;
        ULONG FreeSystemPtes;
        ULONG ResidentSystemCodePage;
        ULONG TotalSystemDriverPages;
        ULONG TotalSystemCodePages;
        ULONG NonPagedPoolLookasideHits;
        ULONG PagedPoolLookasideHits;
        ULONG Spare3Count;
        ULONG ResidentSystemCachePage;
        ULONG ResidentPagedPoolPage;
        ULONG ResidentSystemDriverPage;
        ULONG CcFastReadNoWait;
        ULONG CcFastReadWait;
        ULONG CcFastReadResourceMiss;
        ULONG CcFastReadNotPossible;
        ULONG CcFastMdlReadNoWait;
        ULONG CcFastMdlReadWait;
        ULONG CcFastMdlReadResourceMiss;
        ULONG CcFastMdlReadNotPossible;
        ULONG CcMapDataNoWait;
        ULONG CcMapDataWait;
        ULONG CcMapDataNoWaitMiss;
        ULONG CcMapDataWaitMiss;
        ULONG CcPinMappedDataCount;
        ULONG CcPinReadNoWait;
        ULONG CcPinReadWait;
        ULONG CcPinReadNoWaitMiss;
        ULONG CcPinReadWaitMiss;
        ULONG CcCopyReadNoWait;
        ULONG CcCopyReadWait;
        ULONG CcCopyReadNoWaitMiss;
        ULONG CcCopyReadWaitMiss;
        ULONG CcMdlReadNoWait;
        ULONG CcMdlReadWait;
        ULONG CcMdlReadNoWaitMiss;
        ULONG CcMdlReadWaitMiss;
        ULONG CcReadAheadIos;
        ULONG CcLazyWriteIos;
        ULONG CcLazyWritePages;
        ULONG CcDataFlushes;
        ULONG CcDataPages;
        ULONG ContextSwitches;
        ULONG FirstLevelTbFills;
        ULONG SecondLevelTbFills;
        ULONG SystemCalls;
    } SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

  

    typedef struct _VM_COUNTERS
    {
        ULONG  PeakVirtualSize;
        ULONG  VirtualSize;
        ULONG  PageFaultCount;
        ULONG  PeakWorkingSetSize;
        ULONG  WorkingSetSize;
        ULONG  QuotaPeakPagedPoolUsage;
        ULONG  QuotaPagedPoolUsage;
        ULONG  QuotaPeakNonPagedPoolUsage;
        ULONG  QuotaNonPagedPoolUsage;
        ULONG  PagefileUsage;
        ULONG  PeakPagefileUsage;
        ULONG  PrivatePageCount;
    } VM_COUNTERS;

    typedef struct _SYSTEM_THREADS
    {
        LARGE_INTEGER  KernelTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  CreateTime;
        ULONG  WaitTime;
        PVOID  StartAddress;
        CLIENT_ID  ClientId;
        KPRIORITY  Priority;
        KPRIORITY  BasePriority;
        ULONG  ContextSwitchCount;
        THREAD_STATE  State;
        KWAIT_REASON  WaitReason;
        ULONG Reversed;
    } SYSTEM_THREADS, * PSYSTEM_THREADS;

    typedef struct _SYSTEM_PROCESSES
    {
        ULONG  NextEntryDelta;
        ULONG  ThreadCount;
        LARGE_INTEGER  Reserved1[3];
        LARGE_INTEGER  CreateTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  KernelTime;
        UNICODE_STRING  ProcessName;
        KPRIORITY  BasePriority;
        ULONG  ProcessId;
        ULONG  InheritedFromProcessId;
        ULONG  HandleCount;
        ULONG SessionId;
        ULONG_PTR PageDirectoryBase;
        VM_COUNTERS  VmCounters;
        ULONG  PrivatePageCount;
        IO_COUNTERS  IoCounters;
        SYSTEM_THREADS  Threads[1];
    } SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

    typedef struct _DEBUG_BUFFER
    {
        HANDLE  SectionHandle;
        PVOID  SectionBase;
        PVOID  RemoteSectionBase;
        ULONG  SectionBaseDelta;
        HANDLE  EventPairHandle;
        ULONG  Unknown[2];
        HANDLE  RemoteThreadHandle;
        ULONG  InfoClassMask;
        ULONG  SizeOfInfo;
        ULONG  AllocatedSize;
        ULONG  SectionSize;
        PVOID  ModuleInformation;
        PVOID  BackTraceInformation;
        PVOID  HeapInformation;
        PVOID  LockInformation;
        PVOID  Reserved[8];
    } DEBUG_BUFFER, * PDEBUG_BUFFER;

    typedef struct _DEBUG_LOCK_INFORMATION
    {
        PVOID  Address;
        USHORT  Type;
        USHORT  CreatorBackTraceIndex;
        ULONG  OwnerThreadId;
        ULONG  ActiveCount;
        ULONG  ContentionCount;
        ULONG  EntryCount;
        ULONG  RecursionCount;
        ULONG  NumberOfSharedWaiters;
        ULONG  NumberOfExclusiveWaiters;
    } DEBUG_LOCK_INFORMATION, * PDEBUG_LOCK_INFORMATION;


    typedef struct _LPC_SECTION_WRITE
    {
        ULONG  Length;
        HANDLE  SectionHandle;
        ULONG  SectionOffset;
        ULONG  ViewSize;
        PVOID  ViewBase;
        PVOID  TargetViewBase;
    } LPC_SECTION_WRITE, * PLPC_SECTION_WRITE;

    typedef struct _LPC_SECTION_READ
    {
        ULONG  Length;
        ULONG  ViewSize;
        PVOID  ViewBase;
    } LPC_SECTION_READ, * PLPC_SECTION_READ;

   

   

    

   

   

    typedef struct _RTL_HANDLE_TABLE_ENTRY
    {
        struct _RTL_HANDLE_TABLE_ENTRY* Next;
        PVOID  Object;
    } RTL_HANDLE_TABLE_ENTRY, * PRTL_HANDLE_TABLE_ENTRY;

    typedef struct _RTL_HANDLE_TABLE
    {
        ULONG MaximumNumberOfHandles;
        ULONG SizeOfHandleTableEntry;
        ULONG Unknown01;
        ULONG Unknown02;
        PRTL_HANDLE_TABLE_ENTRY FreeHandles;
        PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
        PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
        PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
    } RTL_HANDLE_TABLE, * PRTL_HANDLE_TABLE;
   

   

    

   

    typedef struct _SYSTEM_VDM_INSTEMUL_INFO
    {
        ULONG SegmentNotPresent;
        ULONG VdmOpcode0F;
        ULONG OpcodeESPrefix;
        ULONG OpcodeCSPrefix;
        ULONG OpcodeSSPrefix;
        ULONG OpcodeDSPrefix;
        ULONG OpcodeFSPrefix;
        ULONG OpcodeGSPrefix;
        ULONG OpcodeOPER32Prefix;
        ULONG OpcodeADDR32Prefix;
        ULONG OpcodeINSB;
        ULONG OpcodeINSW;
        ULONG OpcodeOUTSB;
        ULONG OpcodeOUTSW;
        ULONG OpcodePUSHF;
        ULONG OpcodePOPF;
        ULONG OpcodeINTnn;
        ULONG OpcodeINTO;
        ULONG OpcodeIRET;
        ULONG OpcodeINBimm;
        ULONG OpcodeINWimm;
        ULONG OpcodeOUTBimm;
        ULONG OpcodeOUTWimm;
        ULONG OpcodeINB;
        ULONG OpcodeINW;
        ULONG OpcodeOUTB;
        ULONG OpcodeOUTW;
        ULONG OpcodeLOCKPrefix;
        ULONG OpcodeREPNEPrefix;
        ULONG OpcodeREPPrefix;
        ULONG OpcodeHLT;
        ULONG OpcodeCLI;
        ULONG OpcodeSTI;
        ULONG BopCount;
    } SYSTEM_VDM_INSTEMUL_INFO, * PSYSTEM_VDM_INSTEMUL_INFO;

 

   

    

    
   

    

    

    

    

    

    typedef struct _FILE_BASIC_INFORMATION
    {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        ULONG FileAttributes;
    } FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

    typedef struct _FILE_FULL_EA_INFORMATION
    {
        ULONG NextEntryOffset;
        UCHAR Flags;
        UCHAR EaNameLength;
        USHORT EaValueLength;
        CHAR EaName[1];
    } FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

    typedef struct _SECTION_IMAGE_INFORMATION
    {
        PVOID TransferAddress;
        ULONG ZeroBits;
        ULONG_PTR MaximumStackSize;
        ULONG_PTR CommittedStackSize;
        ULONG SubSystemType;
        union _SECTION_IMAGE_INFORMATION_u0
        {
            struct _SECTION_IMAGE_INFORMATION_s0
            {
                USHORT SubSystemMinorVersion;
                USHORT SubSystemMajorVersion;
            };
            ULONG SubSystemVersion;
        };
        ULONG GpValue;
        USHORT ImageCharacteristics;
        USHORT DllCharacteristics;
        USHORT Machine;
        BOOLEAN ImageContainsCode;
        BOOLEAN Spare1;
        ULONG LoaderFlags;
        ULONG Reserved[2];
    } SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

    typedef struct _RTL_USER_PROCESS_INFORMATION
    {
        ULONG Length;
        HANDLE ProcessHandle;
        HANDLE ThreadHandle;
        CLIENT_ID ClientId;
        SECTION_IMAGE_INFORMATION ImageInformation;
    } RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

    typedef struct _PORT_MESSAGE
    {
        union
        {
            struct
            {
                USHORT DataLength;
                USHORT TotalLength;
            } s1;
            ULONG Length;
        } u1;
        union
        {
            struct
            {
                USHORT Type;
                USHORT DataInfoOffset;
            } s2;
            ULONG ZeroInit;
        } u2;
        union
        {
            CLIENT_ID ClientId;
            double   DoNotUseThisField;
        };
        ULONG  MessageId;
        union
        {
            ULONG_PTR ClientViewSize;
            ULONG  CallbackId;
        };
    } PORT_MESSAGE, * PPORT_MESSAGE;

    typedef struct _PORT_VIEW
    {
        ULONG  Length;
        HANDLE SectionHandle;
        ULONG  SectionOffset;
        SIZE_T ViewSize;
        PVOID  ViewBase;
        PVOID  ViewRemoteBase;
    } PORT_VIEW, * PPORT_VIEW;

    typedef struct _REMOTE_PORT_VIEW
    {
        ULONG  Length;
        SIZE_T ViewSize;
        PVOID  ViewBase;
    } REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

    typedef struct RTL_HEAP_PARAMETERS
    {
        ULONG Length;
        ULONG SegmentReserve;
        ULONG SegmentCommit;
        ULONG DeCommitFreeBlockThreshold;
        ULONG DeCommitTotalFreeThreshold;
        ULONG MaximumAllocationSize;
        ULONG VirtualMemoryThreshold;
        ULONG InitialCommit;
        ULONG InitialReserve;
        PVOID CommitRoutine;
        ULONG Reserved;
    } RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;
#pragma endregion

#pragma region TYPEDEF API

    typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
        IN    PVOID  NormalContext,
        IN    PVOID  SystemArgument1,
        IN    PVOID  SystemArgument2
        );

    typedef VOID(NTAPI* PIO_APC_ROUTINE)(
        IN    PVOID ApcContext,
        IN    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG Reserved
        );

    typedef VOID(NTAPI* PIO_APC_ROUTINE)(
        IN    PVOID ApcContext,
        IN    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG Reserved
        );

    typedef VOID(NTAPI* PUSER_THREAD_START_ROUTINE)(
        IN    PVOID ApcArgument1
        );

#pragma endregion

#pragma region DEFINE API

#ifndef WIN64
#define NtCurrentProcess() ((HANDLE)0xFFFFFFFF)
#define NtCurrentThread() ((HANDLE)0xFFFFFFFE)
#else // WIN64
#define NtCurrentProcess() ((HANDLE)0xFFFFFFFFFFFFFFFF)
#define NtCurrentThread() ((HANDLE)0xFFFFFFFFFFFFFFFE)
#endif // WIN64

#define NtCurrentPeb()     (PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock)

#define RtlProcessHeap() (HANDLE)(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap)

#define DECLARE_INTERNAL_OBJECT(x) struct _##x; typedef struct _##x *P##x;

#define DECLARE_INTERNAL_OBJECT2(x,y) struct _##x; typedef struct _##x *P##y;

#define InitializeObjectAttributes(p, n, a, r, s)    \
 {                                                    \
     (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
     (p)->RootDirectory = r;                            \
     (p)->Attributes = a;                            \
     (p)->ObjectName = n;                            \
     (p)->SecurityDescriptor = s;                    \
     (p)->SecurityQualityOfService = NULL;            \
 }

#define InitializeMessageHeader(ph, l, t)                            \
 {                                                                    \
     (ph)->u1.s1.TotalLength = (USHORT)(l);                            \
     (ph)->u1.s1.DataLength = (USHORT)(l - sizeof(PORT_MESSAGE));    \
     (ph)->u2.s2.Type = (USHORT)(t);                                    \
     (ph)->u2.s2.DataInfoOffset = 0;                                    \
     (ph)->ClientId.UniqueProcess = NULL;                            \
     (ph)->ClientId.UniqueThread = NULL;                                \
     (ph)->MessageId = 0;                                            \
     (ph)->ClientViewSize = 0;                                        \
 }

#define RtlInitEmptyUnicodeString(ucStr, buf, bufSize)    \
{                                                        \
    (ucStr)->Buffer = (buf);                            \
    (ucStr)->Length = 0;                                \
    (ucStr)->MaximumLength = (USHORT)(bufSize);            \
}

#define ABSOLUTE_INTERVAL(wait) (wait)

#define RELATIVE_INTERVAL(wait) (-(wait))

#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILISECONDS(mili) (((signed __int64)(mili)) * MICROSECONDS(1000L))

#define SECONDS(seconds) (((signed __int64)(seconds)) * MILISECONDS(1000L))

#pragma endregion

#pragma region REAL API
    
    constexpr FORCEINLINE bool CheckMask(const DWORD value, const DWORD mask) {//�ж�vakue��mask�Ƿ����
        return (mask && (value & mask)) && (value <= mask);
    }
    
    BOOLEAN FORCEINLINE IsListEmpty(IN    const LIST_ENTRY* ListHead)
    {
        return (BOOLEAN)(ListHead->Flink == ListHead);
    }

    FORCEINLINE VOID InitializeListHead(IN    PLIST_ENTRY ListHead)
    {
        ListHead->Flink = ListHead->Blink = ListHead;
    }

    FORCEINLINE VOID InsertHeadList(IN OUT    PLIST_ENTRY ListHead, IN OUT    PLIST_ENTRY Entry)
    {
        PLIST_ENTRY Flink;
        Flink = ListHead->Flink;
        Entry->Flink = Flink;
        Entry->Blink = ListHead;
        Flink->Blink = Entry;
        ListHead->Flink = Entry;
    }

    FORCEINLINE VOID InsertTailList(IN OUT    PLIST_ENTRY ListHead, IN OUT    PLIST_ENTRY Entry)
    {
        PLIST_ENTRY Blink;
        Blink = ListHead->Blink;
        Entry->Flink = ListHead;
        Entry->Blink = Blink;
        Blink->Flink = Entry;
        ListHead->Blink = Entry;
    }

    FORCEINLINE BOOLEAN RemoveEntryList(IN    PLIST_ENTRY Entry)
    {
        PLIST_ENTRY Blink;
        PLIST_ENTRY Flink;
        Flink = Entry->Flink;
        Blink = Entry->Blink;
        Blink->Flink = Flink;
        Flink->Blink = Blink;
        return (BOOLEAN)(Flink == Blink);
    }

#pragma endregion

#pragma region NATIVE API

    EXPORT NTSTATUS NTAPI NtAcceptConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PVOID PortContext OPTIONAL,
        IN    PPORT_MESSAGE ConnectionRequest,
        IN    BOOLEAN AcceptConnection,
        IN OUT    PPORT_VIEW ServerView OPTIONAL,
        OUT    PREMOTE_PORT_VIEW ClientView OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtAccessCheck(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    PGENERIC_MAPPING GenericMapping,
        OUT    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PBOOLEAN AccessStatus
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ACCESS_MASK DesiredAccess,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PBOOLEAN AccessStatus,
        OUT    PBOOLEAN GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckByType(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    HANDLE TokenHandle,
        IN    ULONG DesiredAccess,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PULONG AccessStatus
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckByTypeAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PULONG AccessStatus,
        OUT    PBOOLEAN GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultList(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList,
        OUT    PULONG GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    HANDLE TokenHandle,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList,
        OUT    PULONG GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtAddAtom(
        IN    PWSTR String,
        IN    ULONG StringLength,
        OUT    PUSHORT Atom
    );

    EXPORT NTSTATUS NTAPI NtAddBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    );

    EXPORT NTSTATUS NTAPI NtAddDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    );

    EXPORT NTSTATUS NTAPI NtAdjustGroupsToken(
        IN    HANDLE TokenHandle,
        IN    BOOLEAN ResetToDefault,
        IN    PTOKEN_GROUPS NewState,
        IN    ULONG BufferLength,
        OUT    PTOKEN_GROUPS PreviousState OPTIONAL,
        OUT    PULONG ReturnLength
    );

    EXPORT NTSTATUS NTAPI NtAdjustPrivilegesToken(
        IN    HANDLE TokenHandle,
        IN    BOOLEAN DisableAllPrivileges,
        IN    PTOKEN_PRIVILEGES NewState OPTIONAL,
        IN    ULONG BufferLength OPTIONAL,
        IN    PTOKEN_PRIVILEGES PreviousState OPTIONAL,
        OUT    PULONG ReturnLength
    );

    EXPORT NTSTATUS NTAPI NtAlertResumeThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtAllocateLocallyUniqueId(
        OUT    PLUID Luid
    );

    EXPORT NTSTATUS NTAPI NtAllocateUserPhysicalPages(
        IN    HANDLE ProcessHandle,
        IN    PULONG NumberOfPages,
        OUT    PULONG PageFrameNumbers
    );

    EXPORT NTSTATUS NTAPI NtAllocateUuids(
        OUT    PLARGE_INTEGER UuidLastTimeAllocated,
        OUT    PULONG UuidDeltaTime,
        OUT    PULONG UuidSequenceNumber,
        OUT    PUCHAR UuidSeed
    );
    EXPORT NTSTATUS NTAPI NtAllocateVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN    ULONG ZeroBits,
        IN OUT    PULONG AllocationSize,
        IN    ULONG AllocationType,
        IN    ULONG Protect
    );

    EXPORT NTSTATUS NTAPI NtAreMappedFilesTheSame(
        IN    PVOID Address1,
        IN    PVOID Address2
    );

    EXPORT NTSTATUS NTAPI NtAssignProcessToJobObject(
        IN    HANDLE JobHandle,
        IN    HANDLE ProcessHandle
    );

    EXPORT NTSTATUS NTAPI NtCallbackReturn(
        IN    PVOID Result OPTIONAL,
        IN    ULONG ResultLength,
        IN    NTSTATUS Status
    );

    EXPORT NTSTATUS NTAPI NtCancelDeviceWakeupRequest(
        IN    HANDLE DeviceHandle
    );

    EXPORT NTSTATUS NTAPI NtCancelIoFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    );

    EXPORT NTSTATUS NTAPI NtCancelTimer(
        IN    HANDLE TimerHandle,
        OUT    PBOOLEAN PreviousState OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtClearEvent(
        IN    HANDLE EventHandle
    );

    EXPORT NTSTATUS NTAPI NtClose(
        IN    HANDLE Handle
    );

    EXPORT NTSTATUS NTAPI NtCloseObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    BOOLEAN GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtCompactKeys(
        IN    ULONG Length,
        IN    HANDLE Key
    );

    EXPORT NTSTATUS NTAPI NtCompareTokens(
        IN    HANDLE FirstTokenHandle,
        IN    HANDLE SecondTokenHandle,
        OUT    PBOOLEAN IdenticalTokens
    );

    EXPORT NTSTATUS NTAPI NtCompleteConnectPort(
        IN    HANDLE PortHandle
    );

    EXPORT NTSTATUS NTAPI NtCompressKey(
        IN    HANDLE Key
    );

    EXPORT NTSTATUS NTAPI NtConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PUNICODE_STRING PortName,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
        IN OUT    PLPC_SECTION_WRITE WriteSection OPTIONAL,
        IN OUT    PLPC_SECTION_READ ReadSection OPTIONAL,
        OUT    PULONG MaxMessageSize OPTIONAL,
        IN OUT    PVOID ConnectData OPTIONAL,
        IN OUT    PULONG ConnectDataLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreateDebugObject(
        OUT    PHANDLE DebugObject,
        IN    ULONG AccessRequired,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    BOOLEAN KillProcessOnExit
    );

    EXPORT NTSTATUS NTAPI NtCreateDirectoryObject(
        OUT    PHANDLE DirectoryHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtCreateEvent(
        OUT    PHANDLE EventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    EVENT_TYPE EventType,
        IN    BOOLEAN InitialState
    );

    EXPORT NTSTATUS NTAPI NtCreateEventPair(
        OUT    PHANDLE EventPairHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreateFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PLARGE_INTEGER AllocationSize OPTIONAL,
        IN    ULONG FileAttributes,
        IN    ULONG ShareAccess,
        IN    ULONG CreateDisposition,
        IN    ULONG CreateOptions,
        IN    PVOID EaBuffer OPTIONAL,
        IN    ULONG EaLength
    );

    EXPORT NTSTATUS NTAPI NtCreateIoCompletion(
        OUT    PHANDLE IoCompletionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG NumberOfConcurrentThreads
    );

    EXPORT NTSTATUS NTAPI NtCreateJobObject(
        OUT    PHANDLE JobHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtCreateJobSet(
        IN    ULONG Jobs,
        IN    PJOB_SET_ARRAY JobSet,
        IN    ULONG Reserved
    );

    EXPORT NTSTATUS NTAPI NtCreateKey(
        OUT    PHANDLE KeyHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG TitleIndex,
        IN    PUNICODE_STRING Class OPTIONAL,
        IN    ULONG CreateOptions,
        OUT    PULONG Disposition OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreateKeyedEvent(
        OUT    PHANDLE KeyedEventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG Reserved
    );

    EXPORT NTSTATUS NTAPI NtCreateMailslotFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG CreateOptions,
        IN    ULONG InBufferSize,
        IN    ULONG MaxMessageSize,
        IN    PLARGE_INTEGER ReadTimeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreateMutant(
        OUT    PHANDLE MutantHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    BOOLEAN InitialOwner
    );

    EXPORT NTSTATUS NTAPI NtCreateNamedPipeFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG ShareAccess,
        IN    ULONG CreateDisposition,
        IN    ULONG CreateOptions,
        IN    BOOLEAN TypeMessage,
        IN    BOOLEAN ReadmodeMessage,
        IN    BOOLEAN Nonblocking,
        IN    ULONG MaxInstances,
        IN    ULONG InBufferSize,
        IN    ULONG OutBufferSize,
        IN    PLARGE_INTEGER DefaultTimeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreatePort(
        OUT    PHANDLE PortHandle,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG MaxConnectionInfoLength,
        IN    ULONG MaxMessageLength,
        IN    ULONG MaxPoolUsage
    );

    EXPORT NTSTATUS NTAPI NtCreateProcess(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    HANDLE ParentProcess,
        IN    BOOLEAN InheritObjectTable,
        IN    HANDLE SectionHandle OPTIONAL,
        IN    HANDLE DebugPort OPTIONAL,
        IN    HANDLE ExceptionPort OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtCreateProcessEx(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    HANDLE InheritFromProcessHandle,
        IN    ULONG CreateFlags,
        IN    HANDLE SectionHandle OPTIONAL,
        IN    HANDLE DebugObject OPTIONAL,
        IN    HANDLE ExceptionPort OPTIONAL,
        IN    ULONG JobMemberLevel
    );

    EXPORT NTSTATUS NTAPI NtCreateProfile(
        OUT    PHANDLE ProfileHandle,
        IN    HANDLE ProcessHandle,
        IN    PVOID Base,
        IN    ULONG Size,
        IN    ULONG BucketShift,
        IN    PULONG Buffer,
        IN    ULONG BufferLength,
        IN    KPROFILE_SOURCE Source,
        IN    ULONG ProcessorMask
    );

    EXPORT NTSTATUS NTAPI NtCreateSection(
        OUT    PHANDLE SectionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PLARGE_INTEGER SectionSize OPTIONAL,
        IN    ULONG Protect,
        IN    ULONG Attributes,
        IN    HANDLE FileHandle
    );

    EXPORT NTSTATUS NTAPI NtCreateSemaphore(
        OUT    PHANDLE SemaphoreHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    ULONG InitialCount,
        IN    ULONG MaximumCount
    );

    EXPORT NTSTATUS NTAPI NtCreateSymbolicLinkObject(
        OUT    PHANDLE SymbolicLinkHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PUNICODE_STRING TargetName
    );


    EXPORT NTSTATUS NTAPI NtCreateToken(
        OUT    PHANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    TOKEN_TYPE Type,
        IN    PLUID AuthenticationId,
        IN    PLARGE_INTEGER ExpirationTime,
        IN    PTOKEN_USER User,
        IN    PTOKEN_GROUPS Groups,
        IN    PTOKEN_PRIVILEGES Privileges,
        IN    PTOKEN_OWNER Owner,
        IN    PTOKEN_PRIMARY_GROUP PrimaryGroup,
        IN    PTOKEN_DEFAULT_DACL DefaultDacl,
        IN    PTOKEN_SOURCE Source
    );

    EXPORT NTSTATUS NTAPI NtCreateWaitablePort(
        OUT    PHANDLE PortHandle,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG MaxConnectionInfoLength,
        IN    ULONG MaxMessageLength,
        IN    ULONG MaxPoolUsage
    );

    EXPORT NTSTATUS NTAPI NtDebugActiveProcess(
        IN    HANDLE Process,
        IN    HANDLE DebugObject
    );

    EXPORT NTSTATUS NTAPI NtDebugContinue(
        IN    HANDLE DebugObject,
        IN    PCLIENT_ID AppClientId,
        IN    NTSTATUS ContinueStatus
    );

    EXPORT NTSTATUS NTAPI NtDelayExecution(
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER DelayInterval
    );

    EXPORT NTSTATUS NTAPI NtDeleteAtom(
        IN    USHORT Atom
    );

    EXPORT NTSTATUS NTAPI NtDeleteBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    );

    EXPORT NTSTATUS NTAPI NtDeleteDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    );

    EXPORT NTSTATUS NTAPI NtDeleteFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtDeleteKey(
        IN    HANDLE KeyHandle
    );

    EXPORT NTSTATUS NTAPI NtDeleteObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    BOOLEAN GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtDeleteValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName
    );

    EXPORT NTSTATUS NTAPI NtDeviceIoControlFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG IoControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    );

    EXPORT NTSTATUS NTAPI NtDisplayString(
        IN    PUNICODE_STRING String
    );

    EXPORT NTSTATUS NTAPI NtDuplicateObject(
        IN    HANDLE SourceProcessHandle,
        IN    HANDLE SourceHandle,
        IN    HANDLE TargetProcessHandle OPTIONAL,
        OUT    PHANDLE TargetHandle OPTIONAL,
        IN    ACCESS_MASK DesiredAccess,
        IN    ULONG HandleAttributes,
        IN    ULONG Options
    );

    EXPORT NTSTATUS NTAPI NtDuplicateToken(
        IN    HANDLE ExistingTokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    BOOLEAN EffectiveOnly,
        IN    TOKEN_TYPE TokenType,
        OUT    PHANDLE NewTokenHandle
    );

    EXPORT NTSTATUS NTAPI NtEnumerateBootEntries(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    );
    EXPORT NTSTATUS NTAPI NtEnumerateKey(
        IN    HANDLE KeyHandle,
        IN    ULONG Index,
        IN    KEY_INFORMATION_CLASS KeyInformationClass,
        OUT    PVOID KeyInformation,
        IN    ULONG KeyInformationLength,
        OUT    PULONG ResultLength
    );

    EXPORT NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2,
        IN    ULONG Unknown3
    );

    EXPORT NTSTATUS NTAPI NtEnumerateValueKey(
        IN    HANDLE KeyHandle,
        IN    ULONG Index,
        IN    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        OUT    PVOID KeyValueInformation,
        IN    ULONG KeyValueInformationLength,
        OUT    PULONG ResultLength
    );

    EXPORT NTSTATUS NTAPI NtExtendSection(
        IN    HANDLE SectionHandle,
        IN    PLARGE_INTEGER SectionSize
    );

    EXPORT NTSTATUS NTAPI NtFilterToken(
        IN    HANDLE ExistingTokenHandle,
        IN    ULONG Flags,
        IN    PTOKEN_GROUPS SidsToDisable,
        IN    PTOKEN_PRIVILEGES PrivilegesToDelete,
        IN    PTOKEN_GROUPS SidsToRestricted,
        OUT    PHANDLE NewTokenHandle
    );

    EXPORT NTSTATUS NTAPI NtFindAtom(
        IN    PWSTR String,
        IN    ULONG StringLength,
        OUT    PUSHORT Atom
    );

    EXPORT NTSTATUS NTAPI NtFlushBuffersFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    );

    EXPORT NTSTATUS NTAPI NtFlushInstructionCache(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress OPTIONAL,
        IN    ULONG FlushSize
    );

    EXPORT NTSTATUS NTAPI NtFlushKey(
        IN    HANDLE KeyHandle
    );

    EXPORT NTSTATUS NTAPI NtFlushVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG FlushSize,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    );

    EXPORT NTSTATUS NTAPI NtFlushWriteBuffer(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtYieldExecution(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtWriteVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWriteRequestData(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message,
        IN    ULONG Index,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWriteFileGather(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_SEGMENT_ELEMENT Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWriteFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWaitLowEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtWaitHighEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtWaitForSingleObject(
        IN    HANDLE Handle,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWaitForMultipleObjects32(
        IN    ULONG HandleCount,
        IN    PHANDLE Handles,
        IN    WAIT_TYPE WaitType,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWaitForMultipleObjects(
        IN    ULONG HandleCount,
        IN    PHANDLE Handles,
        IN    WAIT_TYPE WaitType,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtWaitForKeyedEvent(
        IN    HANDLE KeyedEventHandle,
        IN    PVOID Key,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtUnmapViewOfSection(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress
    );

    EXPORT NTSTATUS NTAPI NtUnlockVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG LockSize,
        IN    ULONG LockType
    );

    EXPORT NTSTATUS NTAPI NtUnlockFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PULARGE_INTEGER LockOffset,
        IN    PULARGE_INTEGER LockLength,
        IN    ULONG Key
    );

    EXPORT NTSTATUS NTAPI NtUnloadKeyEx(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    HANDLE EventHandle OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtUnloadKey2(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    BOOLEAN ForceUnload
    );

    EXPORT NTSTATUS NTAPI NtUnloadKey(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtUnloadDriver(
        IN    PUNICODE_STRING DriverServiceName
    );

    EXPORT NTSTATUS NTAPI NtTerminateThread(
        IN    HANDLE ThreadHandle OPTIONAL,
        IN    NTSTATUS ExitStatus
    );

    EXPORT NTSTATUS NTAPI NtTerminateProcess(
        IN    HANDLE ProcessHandle OPTIONAL,
        IN    NTSTATUS ExitStatus
    );

    EXPORT NTSTATUS NTAPI NtTerminateJobObject(
        IN    HANDLE JobHandle,
        IN    NTSTATUS ExitStatus
    );

    EXPORT NTSTATUS NTAPI NtSystemDebugControl(
        IN    DEBUG_CONTROL_CODE ControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSuspendThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSuspendProcess(
        IN    HANDLE Process
    );

    EXPORT NTSTATUS NTAPI NtStopProfile(
        IN    HANDLE ProfileHandle
    );
    EXPORT NTSTATUS NTAPI NtStartProfile(
        IN    HANDLE ProfileHandle
    );

    EXPORT NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
        IN    HANDLE HandleToSignal,
        IN    HANDLE HandleToWait,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtShutdownSystem(
        IN    SHUTDOWN_ACTION Action
    );

    EXPORT NTSTATUS NTAPI NtSetVolumeInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    FS_INFORMATION_CLASS VolumeInformationClass
    );

    EXPORT NTSTATUS NTAPI NtSetValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName,
        IN    ULONG TitleIndex OPTIONAL,
        IN    ULONG Type,
        IN    PVOID Data,
        IN    ULONG DataSize
    );

    EXPORT NTSTATUS NTAPI NtSetUuidSeed(
        IN    PUCHAR UuidSeed
    );

    EXPORT NTSTATUS NTAPI NtSetTimerResolution(
        IN    ULONG RequestedResolution,
        IN    BOOLEAN Set,
        OUT    PULONG ActualResolution
    );

    EXPORT NTSTATUS NTAPI NtSetThreadExecutionState(
        IN    EXECUTION_STATE ExecutionState,
        OUT    PEXECUTION_STATE PreviousExecutionState
    );

    EXPORT NTSTATUS NTAPI NtSetSystemTime(
        IN    PLARGE_INTEGER NewTime,
        OUT    PLARGE_INTEGER OldTime OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSetSystemPowerState(
        IN    POWER_ACTION SystemAction,
        IN    SYSTEM_POWER_STATE MinSystemState,
        IN    ULONG Flags
    );

    EXPORT NTSTATUS NTAPI NtSetSystemInformation(
        IN    SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IN OUT    PVOID SystemInformation,
        IN    ULONG SystemInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetSystemEnvironmentValue(
        IN    PUNICODE_STRING Name,
        IN    PUNICODE_STRING Value
    );

    EXPORT NTSTATUS NTAPI NtSetSecurityObject(
        IN    HANDLE Handle,
        IN    SECURITY_INFORMATION SecurityInformation,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor
    );

    EXPORT NTSTATUS NTAPI NtSetLowWaitHighEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtSetLowEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtSetLdtEntries(
        IN    ULONG Selector1,
        IN    LDT_ENTRY LdtEntry1,
        IN    ULONG Selector2,
        IN    LDT_ENTRY LdtEntry2
    );

    EXPORT NTSTATUS NTAPI NtSetIoCompletion(
        IN    HANDLE IoCompletionHandle,
        IN    ULONG CompletionKey,
        IN    ULONG CompletionValue,
        IN    NTSTATUS Status,
        IN    ULONG Information
    );

    EXPORT NTSTATUS NTAPI NtSetIntervalProfile(
        IN    ULONG Interval,
        IN    KPROFILE_SOURCE Source
    );

    EXPORT NTSTATUS NTAPI NtSetInformationToken(
        IN    HANDLE TokenHandle,
        IN    TOKEN_INFORMATION_CLASS TokenInformationClass,
        IN    PVOID TokenInformation,
        IN    ULONG TokenInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationThread(
        IN    HANDLE ThreadHandle,
        IN    THREADINFOCLASS ThreadInformationClass,
        IN    PVOID ThreadInformation,
        IN    ULONG ThreadInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationProcess(
        IN    HANDLE ProcessHandle,
        IN    PROCESSINFOCLASS ProcessInformationClass,
        IN    PVOID ProcessInformation,
        IN    ULONG ProcessInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationObject(
        IN    HANDLE ObjectHandle,
        IN    OBJECT_INFORMATION_CLASS ObjectInformationClass,
        IN    PVOID ObjectInformation,
        IN    ULONG ObjectInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationKey(
        IN    HANDLE KeyHandle,
        IN    KEY_SET_INFORMATION_CLASS KeyInformationClass,
        IN    PVOID KeyInformation,
        IN    ULONG KeyInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationJobObject(
        IN    HANDLE JobHandle,
        IN    JOBOBJECTINFOCLASS JobInformationClass,
        IN    PVOID JobInformation,
        IN    ULONG JobInformationLength
    );

    EXPORT NTSTATUS NTAPI NtSetInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass
    );

    EXPORT NTSTATUS NTAPI NtSetHighWaitLowEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtSetHighEventPair(
        IN    HANDLE EventPairHandle
    );

    EXPORT NTSTATUS NTAPI NtSetEventBoostPriority(
        IN    HANDLE EventHandle
    );

    EXPORT NTSTATUS NTAPI NtSetEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSetEaFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_FULL_EA_INFORMATION Buffer,
        IN    ULONG BufferLength
    );

    EXPORT NTSTATUS NTAPI NtSetDefaultUILanguage(
        IN    LANGID LanguageId
    );

    EXPORT NTSTATUS NTAPI NtSetDefaultLocale(
        IN    BOOLEAN ThreadOrSystem,
        IN    LCID Locale
    );

    EXPORT NTSTATUS NTAPI NtSetDefaultHardErrorPort(
        IN    HANDLE PortHandle
    );

    EXPORT NTSTATUS NTAPI NtSetDebugFilterState(
        IN    ULONG ComponentId,
        IN    ULONG Level,
        IN    BOOLEAN Enable
    );


    EXPORT NTSTATUS NTAPI NtSetContextChannel(
        IN    HANDLE CHannelHandle
    );

    EXPORT NTSTATUS NTAPI NtSetBootEntryOrder(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    );

    EXPORT NTSTATUS NTAPI NtSecureConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PUNICODE_STRING PortName,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
        IN OUT    PPORT_VIEW ClientView OPTIONAL,
        IN    PSID ServerSid OPTIONAL,
        OUT    PREMOTE_PORT_VIEW ServerView OPTIONAL,
        OUT    PULONG MaxMessageLength OPTIONAL,
        IN OUT    PVOID ConnectInformation OPTIONAL,
        IN OUT    PULONG ConnectInformationLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSaveMergedKeys(
        IN    HANDLE KeyHandle1,
        IN    HANDLE KeyHandle2,
        IN    HANDLE FileHandle
    );

    EXPORT NTSTATUS NTAPI NtSaveKeyEx(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle,
        IN    ULONG Flags
    );

    EXPORT NTSTATUS NTAPI NtSaveKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle
    );

    EXPORT NTSTATUS NTAPI NtResumeThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtResumeProcess(
        IN    HANDLE Process
    );

    EXPORT NTSTATUS NTAPI NtRestoreKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle,
        IN    ULONG Flags
    );

    EXPORT NTSTATUS NTAPI NtResetWriteWatch(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    ULONG RegionSize
    );

    EXPORT NTSTATUS NTAPI NtResetEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtRequestWakeupLatency(
        IN    LATENCY_TIME Latency
    );

    EXPORT NTSTATUS NTAPI NtRequestWaitReplyPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE RequestMessage,
        OUT    PPORT_MESSAGE ReplyMessage
    );

    EXPORT NTSTATUS NTAPI NtRequestPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE RequestMessage
    );

    EXPORT NTSTATUS NTAPI NtRequestDeviceWakeup(
        IN    HANDLE DeviceHandle
    );

    EXPORT NTSTATUS NTAPI NtReplyWaitReplyPort(
        IN    HANDLE PortHandle,
        IN OUT    PPORT_MESSAGE ReplyMessage
    );

    EXPORT NTSTATUS NTAPI NtReplyWaitReceivePortEx(
        IN    HANDLE PortHandle,
        OUT    PVOID* PortIdentifier OPTIONAL,
        IN    PPORT_MESSAGE ReplyMessage OPTIONAL,
        OUT    PPORT_MESSAGE Message,
        IN    PLARGE_INTEGER Timeout
    );

    EXPORT NTSTATUS NTAPI NtReplyWaitReceivePort(
        IN    HANDLE PortHandle,
        OUT    PULONG PortIdentifier OPTIONAL,
        IN    PPORT_MESSAGE ReplyMessage OPTIONAL,
        OUT    PPORT_MESSAGE Message
    );

    EXPORT NTSTATUS NTAPI NtReplyPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE ReplyMessage
    );

    EXPORT NTSTATUS NTAPI NtReplaceKey(
        IN    POBJECT_ATTRIBUTES NewFileObjectAttributes,
        IN    HANDLE KeyHandle,
        IN    POBJECT_ATTRIBUTES OldFileObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtRenameKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ReplacementName
    );

    EXPORT NTSTATUS NTAPI NtRemoveProcessDebug(
        IN    HANDLE Process,
        IN    HANDLE DebugObject
    );

    EXPORT NTSTATUS NTAPI NtRemoveIoCompletion(
        IN    HANDLE IoCompletionHandle,
        OUT    PULONG CompletionKey,
        OUT    PULONG CompletionValue,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtReleaseSemaphore(
        IN    HANDLE SemaphoreHandle,
        IN    LONG ReleaseCount,
        OUT    PLONG PreviousCount OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtReleaseMutant(
        IN    HANDLE MutantHandle,
        OUT    PULONG PreviousState
    );

    EXPORT NTSTATUS NTAPI NtReleaseKeyedEvent(
        IN    HANDLE KeyedEventHandle,
        IN    PVOID Key,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtRegisterThreadTerminatePort(
        IN    HANDLE PortHandle
    );

    EXPORT NTSTATUS NTAPI NtReadVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtReadRequestData(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message,
        IN    ULONG Index,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtReadFileScatter(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_SEGMENT_ELEMENT Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtReadFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtRaiseHardError(
        IN    NTSTATUS Status,
        IN    ULONG NumberOfArguments,
        IN    ULONG StringArgumentsMask,
        IN    PULONG_PTR Arguments,
        IN    HARDERROR_RESPONSE_OPTION ResponseOption,
        OUT    PHARDERROR_RESPONSE Response
    );

    EXPORT NTSTATUS NTAPI NtQueueApcThread(
        IN    HANDLE ThreadHandle,
        IN    PKNORMAL_ROUTINE ApcRoutine,
        IN    PVOID ApcContext OPTIONAL,
        IN    PVOID Argument1 OPTIONAL,
        IN    PVOID Argument2 OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryVolumeInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID VolumeInformation,
        IN    ULONG VolumeInformationLength,
        IN    FS_INFORMATION_CLASS VolumeInformationClass
    );

    EXPORT NTSTATUS NTAPI NtQueryVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    MEMORY_INFORMATION_CLASS MemoryInformationClass,
        OUT    PVOID MemoryInformation,
        IN    ULONG MemoryInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName,
        IN    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        OUT    PVOID KeyValueInformation,
        IN    ULONG KeyValueInformationLength,
        OUT    PULONG ResultLength
    );

    EXPORT NTSTATUS NTAPI NtQueryTimerResolution(
        OUT    PULONG CoarsestResolution,
        OUT    PULONG FinestResolution,
        OUT    PULONG ActualResolution
    );

    EXPORT NTSTATUS NTAPI NtQuerySystemTime(
        OUT    PLARGE_INTEGER CurrentTime
    );

    EXPORT NTSTATUS NTAPI NtQuerySystemInformation(
        IN    SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IN OUT    PVOID SystemInformation,
        IN    ULONG SystemInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2,
        IN    ULONG Unknown3,
        IN    ULONG Unknown4,
        IN    ULONG Unknown5
    );

    EXPORT NTSTATUS NTAPI NtQuerySystemEnvironmentValue(
        IN    PUNICODE_STRING Name,
        OUT    PVOID Value,
        IN    ULONG ValueLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQuerySymbolicLinkObject(
        IN    HANDLE SymbolicLinkHandle,
        IN OUT    PUNICODE_STRING TargetName,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQuerySecurityObject(
        IN    HANDLE ObjectHandle,
        IN    SECURITY_INFORMATION SecurityInformation,
        OUT    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ULONG DescriptorLength,
        OUT    PULONG ReturnLength
    );

    EXPORT NTSTATUS NTAPI NtQuerySection(
        IN    HANDLE SectionHandle,
        IN    SECTION_INFORMATION_CLASS SectionInformationClass,
        OUT    PVOID SectionInformation,
        IN    ULONG SectionInformationLength,
        OUT    PULONG ResultLength OPTIONAL
    );

    EXPORT BOOLEAN NTAPI NtQueryPortInformationProcess(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtQueryPerformanceCounter(
        OUT    PLARGE_INTEGER PerformanceCount,
        OUT    PLARGE_INTEGER PerformanceFrequency OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryOpenSubKeys(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        OUT    PULONG NumberOfKeys
    );

    EXPORT NTSTATUS NTAPI NtQueryObject(
        IN    HANDLE ObjectHandle,
        IN    OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT    PVOID ObjectInformation,
        IN    ULONG ObjectInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryMultipleValueKey(
        IN    HANDLE KeyHandle,
        IN OUT    PKEY_VALUE_ENTRY ValueList,
        IN    ULONG NumberOfValues,
        OUT    PVOID Buffer,
        IN OUT    PULONG Length,
        OUT    PULONG ReturnLength
    );

    EXPORT NTSTATUS NTAPI NtQueryKey(
        IN    HANDLE KeyHandle,
        IN    KEY_INFORMATION_CLASS KeyInformationClass,
        OUT    PVOID KeyInformation,
        IN    ULONG KeyInformationLength,
        OUT    PULONG ResultLength
    );

    EXPORT NTSTATUS NTAPI NtQueryIntervalProfile(
        IN    KPROFILE_SOURCE Source,
        OUT    PULONG Interval
    );

    EXPORT NTSTATUS NTAPI NtQueryInstallUILanguage(
        OUT    PLANGID LanguageId
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationToken(
        IN    HANDLE TokenHandle,
        IN    TOKEN_INFORMATION_CLASS TokenInformationClass,
        OUT    PVOID TokenInformation,
        IN    ULONG TokenInformationLength,
        OUT    PULONG ReturnLength
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationThread(
        IN    HANDLE ThreadHandle,
        IN    THREADINFOCLASS ThreadInformationClass,
        OUT    PVOID ThreadInformation,
        IN    ULONG ThreadInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationProcess(
        IN    HANDLE ProcessHandle,
        IN    PROCESSINFOCLASS ProcessInformationClass,
        OUT    PVOID ProcessInformation,
        IN    ULONG ProcessInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationPort(
        IN    HANDLE PortHandle,
        IN    PORT_INFORMATION_CLASS PortInformationClass,
        OUT    PVOID PortInformation,
        IN    ULONG PortInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationJobObject(
        IN    HANDLE JobHandle,
        IN    JOBOBJECTINFOCLASS JobInformationClass,
        OUT    PVOID JobInformation,
        IN    ULONG JobInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass
    );

    EXPORT NTSTATUS NTAPI NtQueryInformationAtom(
        IN    USHORT Atom,
        IN    ATOM_INFORMATION_CLASS AtomInformationClass,
        OUT    PVOID AtomInformation,
        IN    ULONG AtomInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryFullAttributesFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );

    EXPORT NTSTATUS NTAPI NtQueryEvent(
        IN    HANDLE EventHandle,
        IN    EVENT_INFORMATION_CLASS EventInformationClass,
        OUT    PVOID EventInformation,
        IN    ULONG EventInformationLength,
        OUT    PULONG ResultLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryDirectoryObject(
        IN    HANDLE DirectoryHandle,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN ReturnSingleEntry,
        IN    BOOLEAN RestartScan,
        IN OUT    PULONG Context,
        OUT    PULONG ReturnLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtQueryDirectoryFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass,
        IN    BOOLEAN ReturnSingleEntry,
        IN    PUNICODE_STRING FileName OPTIONAL,
        IN    BOOLEAN RestartScan
    );

    EXPORT NTSTATUS NTAPI NtQueryDefaultUILanguage(
        OUT    PLANGID LanguageId
    );

    EXPORT NTSTATUS NTAPI NtQueryDefaultLocale(
        IN    BOOLEAN ThreadOrSystem,
        OUT    PLCID Locale
    );

    EXPORT NTSTATUS NTAPI NtQueryDebugFilterState(
        IN    ULONG ComponentId,
        IN    ULONG Level
    );

    EXPORT NTSTATUS NTAPI NtQueryBootOptions(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    );

    EXPORT NTSTATUS NTAPI NtQueryBootEntryOrder(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    );

    EXPORT NTSTATUS NTAPI NtQueryAttributesFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PFILE_BASIC_INFORMATION FileInformation
    );

    EXPORT NTSTATUS NTAPI NtPulseEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtProtectVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG ProtectSize,
        IN    ULONG NewProtect,
        OUT    PULONG OldProtect
    );

    EXPORT NTSTATUS NTAPI NtPrivilegedServiceAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PUNICODE_STRING ServiceName,
        IN    HANDLE TokenHandle,
        IN    PPRIVILEGE_SET Privileges,
        IN    BOOLEAN AccessGranted
    );

    EXPORT NTSTATUS NTAPI NtPrivilegeObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    PPRIVILEGE_SET Privileges,
        IN    BOOLEAN AccessGranted
    );

    EXPORT NTSTATUS NTAPI NtPrivilegeCheck(
        IN    HANDLE TokenHandle,
        IN    PPRIVILEGE_SET RequiredPrivileges,
        OUT    PBOOLEAN Result
    );

    EXPORT NTSTATUS NTAPI NtPowerInformation(
        IN    POWER_INFORMATION_LEVEL PowerInformationLevel,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    );

    EXPORT NTSTATUS NTAPI NtPlugPlayControl(
        IN    ULONG ControlCode,
        IN OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    PVOID Unknown OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtOpenTimer(
        OUT    PHANDLE TimerHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenThreadTokenEx(
        IN    HANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    BOOLEAN OpenAsSelf,
        IN    ULONG HandleAttributes,
        OUT    PHANDLE TokenHandle
    );

    EXPORT NTSTATUS NTAPI NtOpenThreadToken(
        IN    HANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    BOOLEAN OpenAsSelf,
        OUT    PHANDLE TokenHandle
    );

    EXPORT NTSTATUS NTAPI NtOpenThread(
        OUT    PHANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PCLIENT_ID ClientId
    );

    EXPORT NTSTATUS NTAPI NtOpenSymbolicLinkObject(
        OUT    PHANDLE SymbolicLinkHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenSemaphore(
        OUT    PHANDLE SemaphoreHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtOpenSection(
        OUT    PHANDLE SectionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenProcessTokenEx(
        IN    HANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    ULONG HandleAttributes,
        OUT    PHANDLE TokenHandle
    );

    EXPORT NTSTATUS NTAPI NtOpenProcessToken(
        IN    HANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        OUT    PHANDLE TokenHandle
    );

    EXPORT NTSTATUS NTAPI NtOpenProcess(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PCLIENT_ID ClientId OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtOpenObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID* HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    ACCESS_MASK GrantedAccess,
        IN    PPRIVILEGE_SET Privileges OPTIONAL,
        IN    BOOLEAN ObjectCreation,
        IN    BOOLEAN AccessGranted,
        OUT    PBOOLEAN GenerateOnClose
    );

    EXPORT NTSTATUS NTAPI NtOpenMutant(
        OUT    PHANDLE MutantHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtOpenKeyedEvent(
        OUT    PHANDLE KeyedEventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenKey(
        OUT    PHANDLE KeyHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenJobObject(
        OUT    PHANDLE JobHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenIoCompletion(
        OUT    PHANDLE IoCompletionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG ShareAccess,
        IN    ULONG OpenOptions
    );

    EXPORT NTSTATUS NTAPI NtOpenEventPair(
        OUT    PHANDLE EventPairHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtOpenEvent(
        OUT    PHANDLE EventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtOpenDirectoryObject(
        OUT    PHANDLE DirectoryHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtNotifyChangeMultipleKeys(
        IN    HANDLE KeyHandle,
        IN    ULONG Flags,
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    HANDLE EventHandle OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN Asynchronous
    );

    EXPORT NTSTATUS NTAPI NtNotifyChangeKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE EventHandle OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN Asynchronous
    );

    EXPORT NTSTATUS NTAPI NtNotifyChangeDirectoryFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PFILE_NOTIFY_INFORMATION Buffer,
        IN    ULONG BufferLength,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree
    );

    EXPORT NTSTATUS NTAPI NtModifyDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    );

    EXPORT NTSTATUS NTAPI NtModifyBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    );

    EXPORT NTSTATUS NTAPI NtMapViewOfSection(
        IN    HANDLE SectionHandle,
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN    ULONG ZeroBits,
        IN    ULONG CommitSize,
        IN OUT    PLARGE_INTEGER SectionOffset OPTIONAL,
        IN OUT    PULONG ViewSize,
        IN    SECTION_INHERIT InheritDisposition,
        IN    ULONG AllocationType,
        IN    ULONG Protect
    );

    EXPORT NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
        IN    PVOID* BaseAddresses,
        IN    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    );

    EXPORT NTSTATUS NTAPI NtMapUserPhysicalPages(
        IN    PVOID BaseAddress,
        IN    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    );

    EXPORT NTSTATUS NTAPI NtMakeTemporaryObject(
        IN    HANDLE ObjectHandle
    );

    EXPORT NTSTATUS NTAPI NtMakePermanentObject(
        IN    HANDLE Object
    );

    EXPORT NTSTATUS NTAPI NtLockVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG LockSize,
        IN    ULONG LockType
    );

    EXPORT NTSTATUS NTAPI NtLockRegistryKey(
        IN    HANDLE Key
    );

    EXPORT NTSTATUS NTAPI NtLockFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PULARGE_INTEGER LockOffset,
        IN    PULARGE_INTEGER LockLength,
        IN    ULONG Key,
        IN    BOOLEAN FailImmediately,
        IN    BOOLEAN ExclusiveLock
    );

    EXPORT NTSTATUS NTAPI NtLoadKey(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    POBJECT_ATTRIBUTES FileObjectAttributes
    );

    EXPORT NTSTATUS NTAPI NtLoadKey2(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    POBJECT_ATTRIBUTES FileObjectAttributes,
        IN    ULONG Flags
    );

    EXPORT NTSTATUS NTAPI NtLoadDriver(
        IN    PUNICODE_STRING DriverServiceName
    );

    EXPORT NTSTATUS NTAPI NtListenPort(
        IN    HANDLE PortHandle,
        OUT    PPORT_MESSAGE RequestMessage
    );

    EXPORT NTSTATUS NTAPI NtFreeUserPhysicalPages(
        IN    HANDLE ProcessHandle,
        IN OUT    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    );

    EXPORT NTSTATUS NTAPI NtFreeVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG FreeSize,
        IN    ULONG FreeType
    );

    EXPORT NTSTATUS NTAPI NtFsControlFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG FsControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    );

    EXPORT NTSTATUS NTAPI NtGetDevicePowerState(
        IN    HANDLE DeviceHandle,
        OUT    PDEVICE_POWER_STATE DevicePowerState
    );

    EXPORT NTSTATUS NTAPI NtGetPlugPlayEvent(
        IN    ULONG Reserved1,
        IN    ULONG Reserved2,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength
    );

    EXPORT NTSTATUS NTAPI NtGetWriteWatch(
        IN    HANDLE ProcessHandle,
        IN    ULONG Flags,
        IN    PVOID BaseAddress,
        IN    ULONG RegionSize,
        OUT    PULONG Buffer,
        IN OUT    PULONG BufferEntries,
        OUT    PULONG Granularity
    );

    EXPORT NTSTATUS NTAPI NtImpersonateAnonymousToken(
        IN    HANDLE ThreadHandle
    );

    EXPORT NTSTATUS NTAPI NtImpersonateClientOfPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message
    );

    EXPORT NTSTATUS NTAPI NtImpersonateThread(
        IN    HANDLE ThreadHandle,
        IN    HANDLE TargetThreadHandle,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos
    );

    EXPORT NTSTATUS NTAPI NtInitializeRegistry(
        IN    BOOLEAN Setup
    );

    EXPORT NTSTATUS NTAPI NtInitiatePowerAction(
        IN    POWER_ACTION SystemAction,
        IN    SYSTEM_POWER_STATE MinSystemState,
        IN    ULONG Flags,
        IN    BOOLEAN Asynchronous
    );

    EXPORT NTSTATUS NTAPI NtIsProcessInJob(
        IN    HANDLE ProcessHandle,
        IN    HANDLE JobHandle OPTIONAL
    );

    EXPORT BOOLEAN NTAPI NtIsSystemResumeAutomatic(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtTestAlert(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtAlertThread(
        IN    HANDLE ThreadHandle
    );

    EXPORT ULONG NTAPI NtGetTickCount(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtW32Call(
        IN    ULONG RoutineIndex,
        IN    PVOID Argument,
        IN    ULONG ArgumentLength,
        OUT    PVOID* Result OPTIONAL,
        OUT    PULONG ResultLength OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtSetLowWaitHighThread(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtSetHighWaitLowThread(
        VOID
    );

    EXPORT NTSTATUS NTAPI NtCreatePagingFile(
        IN    PUNICODE_STRING FileName,
        IN    PULARGE_INTEGER InitialSize,
        IN    PULARGE_INTEGER MaximumSize,
        IN    ULONG Priority OPTIONAL
    );

    EXPORT NTSTATUS NTAPI NtVdmControl(
        IN    ULONG ControlCode,
        IN    PVOID ControlData
    );

    EXPORT NTSTATUS NTAPI NtQueryEaFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID Buffer,
        IN    ULONG Length,
        IN    BOOLEAN ReturnSingleEntry,
        IN    PVOID EaList OPTIONAL,
        IN    ULONG EaListLength,
        IN    PULONG EaIndex OPTIONAL,
        IN    BOOLEAN RestartScan
    );

    NTSTATUS NTAPI RtlCreateProcessParameters(
        OUT    PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
        IN    PUNICODE_STRING ImageFile,
        IN    PUNICODE_STRING DllPath OPTIONAL,
        IN    PUNICODE_STRING CurrentDirectory OPTIONAL,
        IN    PUNICODE_STRING CommandLine OPTIONAL,
        IN    PWSTR Environment OPTIONAL,
        IN    PUNICODE_STRING WindowTitle OPTIONAL,
        IN    PUNICODE_STRING DesktopInfo OPTIONAL,
        IN    PUNICODE_STRING ShellInfo OPTIONAL,
        IN    PUNICODE_STRING RuntimeInfo OPTIONAL
    );

    NTSTATUS NTAPI RtlDestroyProcessParameters(
        IN    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

    PDEBUG_BUFFER NTAPI RtlCreateQueryDebugBuffer(
        IN    ULONG Size,
        IN    BOOLEAN EventPair
    );

    NTSTATUS NTAPI RtlQueryProcessDebugInformation(
        IN    ULONG ProcessId,
        IN    ULONG DebugInfoClassMask,
        IN OUT    PDEBUG_BUFFER DebugBuffer
    );

    NTSTATUS NTAPI RtlDestroyQueryDebugBuffer(
        IN    PDEBUG_BUFFER DebugBuffer
    );

    EXPORT VOID NTAPI RtlInitUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PCWSTR SourceString
    );

    EXPORT VOID NTAPI RtlInitString(
        PSTRING DestinationString,
        PCSTR SourceString
    );

    EXPORT VOID NTAPI RtlInitAnsiString(
        OUT    PANSI_STRING DestinationString,
        IN    PCSTR SourceString
    );

    EXPORT NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PANSI_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    );

    EXPORT NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
        OUT    PANSI_STRING DestinationString,
        IN    PCUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    );

    EXPORT LONG NTAPI RtlCompareUnicodeString(
        IN    PUNICODE_STRING String1,
        IN    PUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    );

    EXPORT BOOLEAN NTAPI RtlEqualUnicodeString(
        IN    PCUNICODE_STRING String1,
        IN    PCUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    );

    EXPORT NTSTATUS NTAPI RtlHashUnicodeString(
        IN    CONST UNICODE_STRING* String,
        IN    BOOLEAN CaseInSensitive,
        IN    ULONG HashAlgorithm,
        OUT    PULONG HashValue
    );

    EXPORT VOID NTAPI RtlCopyUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString
    );

    EXPORT NTSTATUS NTAPI RtlAppendUnicodeStringToString(
        IN OUT    PUNICODE_STRING Destination,
        IN    PUNICODE_STRING Source
    );

    EXPORT NTSTATUS NTAPI RtlAppendUnicodeToString(
        PUNICODE_STRING Destination,
        PCWSTR Source
    );

    EXPORT VOID NTAPI RtlFreeUnicodeString(
        PUNICODE_STRING UnicodeString
    );

    EXPORT VOID NTAPI RtlFreeAnsiString(
        PANSI_STRING AnsiString
    );

    EXPORT ULONG NTAPI RtlxUnicodeStringToAnsiSize(
        PCUNICODE_STRING UnicodeString
    );

    EXPORT DWORD NTAPI RtlNtStatusToDosError(
        IN    NTSTATUS status
    );

    EXPORT NTSTATUS NTAPI RtlAdjustPrivilege(
        ULONG  Privilege,
        BOOLEAN Enable,
        BOOLEAN CurrentThread,
        PBOOLEAN Enabled
    );

    EXPORT BOOLEAN NTAPI RtlCreateUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PCWSTR SourceString
    );

    EXPORT BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz(
        OUT    PUNICODE_STRING Destination,
        IN    PCSTR Source
    );

    EXPORT BOOLEAN NTAPI RtlPrefixUnicodeString(
        IN    PUNICODE_STRING String1,
        IN    PUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    );

    EXPORT NTSTATUS NTAPI RtlDuplicateUnicodeString(
        IN    BOOLEAN AllocateNew,
        IN    PUNICODE_STRING SourceString,
        OUT    PUNICODE_STRING TargetString
    );

    EXPORT NTSTATUS NTAPI RtlUnicodeStringToInteger(
        IN    PUNICODE_STRING String,
        IN    ULONG Base OPTIONAL,
        OUT    PULONG Value
    );

    EXPORT NTSTATUS NTAPI RtlIntegerToUnicodeString(
        IN    ULONG Value,
        IN    ULONG Base OPTIONAL,
        IN OUT    PUNICODE_STRING String
    );

    EXPORT NTSTATUS NTAPI RtlGUIDFromString(
        IN    PUNICODE_STRING GuidString,
        OUT    GUID* Guid
    );

    EXPORT NTSTATUS NTAPI RtlUpcaseUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    );

    EXPORT NTSTATUS NTAPI RtlDowncaseUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    );

    EXPORT NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(
        OUT    PUNICODE_STRING CurrentUserKeyPath
    );

    EXPORT VOID NTAPI RtlRaiseStatus(
        IN    NTSTATUS Status
    );

    EXPORT ULONG NTAPI RtlRandom(
        IN OUT    PULONG Seed
    );

    EXPORT NTSTATUS NTAPI RtlInitializeCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    );

    EXPORT BOOL NTAPI RtlTryEnterCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    );

    EXPORT NTSTATUS NTAPI RtlEnterCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    );

    EXPORT NTSTATUS NTAPI RtlLeaveCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    );

    EXPORT NTSTATUS NTAPI RtlDeleteCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    );

    EXPORT NTSTATUS NTAPI RtlCompressBuffer(
        IN    USHORT CompressionFormatAndEngine,
        IN    PUCHAR UncompressedBuffer,
        IN    ULONG UncompressedBufferSize,
        OUT    PUCHAR CompressedBuffer,
        IN    ULONG CompressedBufferSize,
        IN    ULONG UncompressedChunkSize,
        OUT    PULONG FinalCompressedSize,
        IN    PVOID WorkSpace
    );

    EXPORT NTSTATUS NTAPI RtlDecompressBuffer(
        IN    USHORT CompressionFormat,
        OUT    PUCHAR UncompressedBuffer,
        IN    ULONG UncompressedBufferSize,
        IN    PUCHAR CompressedBuffer,
        IN    ULONG CompressedBufferSize,
        OUT    PULONG FinalUncompressedSize
    );

    EXPORT VOID NTAPI RtlInitializeHandleTable(
        IN    ULONG MaximumNumberOfHandles,
        IN    ULONG SizeOfHandleTableEntry,
        OUT    PRTL_HANDLE_TABLE HandleTable
    );

    EXPORT PRTL_HANDLE_TABLE_ENTRY NTAPI RtlAllocateHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        OUT    PULONG HandleIndex OPTIONAL
    );

    EXPORT BOOLEAN NTAPI RtlFreeHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        IN    PRTL_HANDLE_TABLE_ENTRY Handle
    );

    EXPORT BOOLEAN NTAPI RtlIsValidIndexHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        IN    ULONG HandleIndex,
        OUT    PRTL_HANDLE_TABLE_ENTRY* Handle
    );

    EXPORT NTSTATUS NTAPI RtlOpenCurrentUser(
        IN    ULONG DesiredAccess,
        OUT    PHANDLE CurrentUserKey
    );

    EXPORT NTSTATUS NTAPI RtlCreateEnvironment(
        BOOLEAN CloneCurrentEnvironment,
        PVOID* Environment
    );

    EXPORT NTSTATUS NTAPI RtlQueryEnvironmentVariable_U(
        PVOID Environment,
        PUNICODE_STRING Name,
        PUNICODE_STRING Value
    );

    EXPORT NTSTATUS NTAPI RtlSetEnvironmentVariable(
        PVOID* Environment,
        PUNICODE_STRING Name,
        PUNICODE_STRING Value
    );

    EXPORT NTSTATUS NTAPI RtlDestroyEnvironment(
        PVOID Environment
    );

    EXPORT BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
        IN    PWSTR DosPathName,
        OUT    PUNICODE_STRING NtPathName,
        OUT    PWSTR* NtFileNamePart OPTIONAL,
        OUT    PCURDIR DirectoryInfo OPTIONAL
    );

    EXPORT NTSTATUS NTAPI RtlCreateUserProcess(
        PUNICODE_STRING NtImagePathName,
        ULONG Attributes,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        HANDLE ParentProcess,
        BOOLEAN InheritHandles,
        HANDLE DebugPort,
        HANDLE ExceptionPort,
        PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

    EXPORT NTSTATUS NTAPI RtlCreateUserThread(
        IN    HANDLE Process,
        IN    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
        IN    BOOLEAN CreateSuspended,
        IN    ULONG_PTR ZeroBits OPTIONAL,
        IN    SIZE_T MaximumStackSize OPTIONAL,
        IN    SIZE_T CommittedStackSize OPTIONAL,
        IN    PUSER_THREAD_START_ROUTINE StartAddress,
        IN    PVOID Parameter OPTIONAL,
        OUT    PHANDLE Thread OPTIONAL,
        OUT    PCLIENT_ID ClientId OPTIONAL
    );

    EXPORT HANDLE NTAPI RtlCreateHeap(
        IN    ULONG Flags,
        IN    PVOID BaseAddress OPTIONAL,
        IN    ULONG SizeToReserve,
        IN    ULONG SizeToCommit,
        IN    BOOLEAN Lock OPTIONAL,
        IN    PRTL_HEAP_PARAMETERS Definition OPTIONAL
    );

    EXPORT ULONG NTAPI RtlDestroyHeap(
        IN    HANDLE HeapHandle
    );

    EXPORT PVOID NTAPI RtlAllocateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    SIZE_T Size
    );

    EXPORT PVOID NTAPI RtlReAllocateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    LPVOID Address,
        IN    SIZE_T Size
    );

    EXPORT BOOLEAN NTAPI RtlFreeHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address
    );

    EXPORT ULONG NTAPI RtlCompactHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags
    );

    EXPORT BOOLEAN NTAPI RtlLockHeap(
        IN    HANDLE HeapHandle
    );

    EXPORT BOOLEAN NTAPI RtlUnlockHeap(
        IN    HANDLE HeapHandle
    );

    EXPORT ULONG NTAPI RtlSizeHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address
    );

    EXPORT BOOLEAN NTAPI RtlValidateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address OPTIONAL
    );

    EXPORT NTSTATUS NTAPI RtlCreateSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ULONG Revision
    );

    EXPORT NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        OUT    PBOOLEAN DaclPresent,
        OUT    PACL* Dacl,
        OUT    PBOOLEAN DaclDefaulted
    );

    EXPORT NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    BOOLEAN DaclPresent,
        IN    PACL Dacl OPTIONAL,
        IN    BOOLEAN DaclDefaulted OPTIONAL
    );

    EXPORT NTSTATUS NTAPI RtlSetOwnerSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID Owner OPTIONAL,
        IN    BOOLEAN OwnerDefaulted OPTIONAL
    );

    EXPORT NTSTATUS NTAPI RtlAllocateAndInitializeSid(
        IN    PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        IN    UCHAR SubAuthorityCount,
        IN    ULONG SubAuthority0,
        IN    ULONG SubAuthority1,
        IN    ULONG SubAuthority2,
        IN    ULONG SubAuthority3,
        IN    ULONG SubAuthority4,
        IN    ULONG SubAuthority5,
        IN    ULONG SubAuthority6,
        IN    ULONG SubAuthority7,
        OUT    PSID* Sid
    );

    EXPORT ULONG NTAPI RtlLengthSid(
        IN    PSID Sid
    );

    EXPORT BOOLEAN NTAPI RtlEqualSid(
        IN    PSID Sid1,
        IN    PSID Sid2
    );

    EXPORT PVOID NTAPI RtlFreeSid(
        IN    PSID Sid
    );

    EXPORT NTSTATUS NTAPI RtlCreateAcl(
        IN    PACL Acl,
        IN    ULONG AclLength,
        IN    ULONG AclRevision
    );

    EXPORT NTSTATUS NTAPI RtlGetAce(
        IN    PACL Acl,
        IN    ULONG AceIndex,
        OUT    PVOID* Ace
    );

    EXPORT NTSTATUS NTAPI RtlAddAccessAllowedAce(
        IN OUT    PACL Acl,
        IN    ULONG AceRevision,
        IN    ACCESS_MASK AccessMask,
        IN    PSID Sid
    );

    EXPORT NTSTATUS NTAPI RtlAddAccessAllowedAceEx(
        IN OUT    PACL Acl,
        IN    ULONG AceRevision,
        IN    ULONG AceFlags,
        IN    ULONG AccessMask,
        IN    PSID Sid
    );

    EXPORT ULONG NTAPI RtlNtStatusToDosErrorNoTeb(
        NTSTATUS Status
    );

    EXPORT NTSTATUS NTAPI RtlGetLastNtStatus(
    );

    EXPORT ULONG NTAPI RtlGetLastWin32Error(
    );

    EXPORT VOID NTAPI RtlSetLastWin32Error(
        ULONG WinError
    );

    EXPORT VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
        NTSTATUS Status
    );

    EXPORT VOID NTAPI DbgBreakPoint(
        VOID
    );

    EXPORT ULONG _cdecl DbgPrint(
        PCH Format,
        ...
    );

    EXPORT NTSTATUS NTAPI LdrLoadDll(
        IN    PWSTR DllPath OPTIONAL,
        IN    PULONG DllCharacteristics OPTIONAL,
        IN    PUNICODE_STRING DllName,
        OUT    PVOID* DllHandle
    );

    EXPORT NTSTATUS NTAPI LdrGetDllHandle(
        IN    PWSTR DllPath OPTIONAL,
        IN    PULONG DllCharacteristics OPTIONAL,
        IN    PUNICODE_STRING DllName,
        OUT    PVOID* DllHandle
    );

    EXPORT NTSTATUS NTAPI LdrUnloadDll(
        IN    PVOID DllHandle
    );

    EXPORT NTSTATUS NTAPI LdrGetProcedureAddress(
        IN    PVOID DllHandle,
        IN    PANSI_STRING ProcedureName OPTIONAL,
        IN    ULONG ProcedureNumber OPTIONAL,
        OUT    PVOID* ProcedureAddress
    );
    EXPORT NTSTATUS NTAPI NtCreateThread(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PCLIENT_ID ClientId,
        PCONTEXT ThreadContext,
        PINITIAL_TEB InitialTeb,
        BOOLEAN CreateSuspended
    );
    EXPORT NTSTATUS NTAPI NtGetThreadContext(
        HANDLE ThreadHandle,
        PCONTEXT Context
    );
    EXPORT NTSTATUS NTAPI NtSetThreadContext(
        HANDLE ThreadHandle,
        PCONTEXT Context
    );
#pragma endregion

#pragma region TAIL

#ifdef __cplusplus
} // extern "C"
#endif

#pragma endregion

#endif // __NTDLL_H__