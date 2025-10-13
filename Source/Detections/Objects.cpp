#include "../Header.h"

namespace Vicra {
VOID ObjectDetection::ForEachHandle( HandlerFunction Handler ) {
	auto shi = Query< PSYSTEM_HANDLE_INFORMATION_EX >(
		SystemExtendedHandleInformation
	);

	for ( int i = 0; i < shi->NumberOfHandles; i++ ) {
		auto& HandleInfo = shi->Handles[ i ];

		auto SourceProcess = std::make_unique< Process >( );
		if ( !SourceProcess->Attach(
			( DWORD )HandleInfo.UniqueProcessId,
			PROCESS_DUP_HANDLE
		) ) continue;

		HANDLE DuplicatedHandle =
			SourceProcess->DuplicateHandle( HandleInfo.HandleValue );

		SourceProcess->Close( );
		if ( DuplicatedHandle == INVALID_HANDLE_VALUE ) continue;

		/*
			Create name mapping
		*/
		if ( m_NameMappings.find( HandleInfo.ObjectTypeIndex ) == m_NameMappings.end( ) ) {
			auto Info = QueryObject< POBJECT_TYPE_INFORMATION >( ObjectTypeInformation, DuplicatedHandle );
			if ( !Info ) continue;

			m_NameMappings.insert( {
				HandleInfo.ObjectTypeIndex,
				{
					Info->TypeName.Buffer,
					Info->TypeName.Length / sizeof( WCHAR )
				}
			} );
		}

		Handler(
			m_NameMappings[ HandleInfo.ObjectTypeIndex ],

			DuplicatedHandle,
			HandleInfo
		);

		NtClose( DuplicatedHandle );
	}
}
VOID ObjectDetection::ResolveOffsets( const std::shared_ptr< Driver >& Driver ) {
	ANSI_STRING PsGetProcessActiveThreadCountName {};
	ANSI_STRING PsIsThreadTerminatingName {};
	ANSI_STRING PsGetThreadIdName {};
	ANSI_STRING PsIsSystemThreadName {};

	RtlInitAnsiString( &PsGetProcessActiveThreadCountName, "PsGetProcessActiveThreadCount" );
	RtlInitAnsiString( &PsIsThreadTerminatingName, "PsIsThreadTerminating" );
	RtlInitAnsiString( &PsGetThreadIdName, "PsGetThreadId" );
	RtlInitAnsiString( &PsIsSystemThreadName, "PsIsSystemThread" );

	PBYTE pPsGetProcessActiveThreadCount = NULL;
	PBYTE pPsIsThreadTerminating = NULL;
	PBYTE pPsGetThreadId = NULL;
	PBYTE pPsIsSystemThread = NULL;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		Driver->NtosKrnl, &PsGetProcessActiveThreadCountName,
		NULL, ( PPVOID )&pPsGetProcessActiveThreadCount
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		Driver->NtosKrnl, &PsIsThreadTerminatingName,
		NULL, ( PPVOID )&pPsIsThreadTerminating
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		Driver->NtosKrnl, &PsGetThreadIdName,
		NULL, ( PPVOID )&pPsGetThreadId
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		Driver->NtosKrnl, &PsIsSystemThreadName,
		NULL, ( PPVOID )&pPsIsSystemThread
	) ) ) return;

	/*
		mov     eax, [rcx+380h]
		retn

		struct _LIST_ENTRY ThreadListHead;                                      //0x370
		volatile ULONG ActiveThreads;                                           //0x380
	*/
	m_ThreadListHeadOffset = reinterpret_cast< PSHORT >( pPsGetProcessActiveThreadCount + 0x2 )[ 0 ] - 0x10;

	/*
		mov     eax, [rcx+5A0h]
		and     al, 1
		retn
	*/
	m_CrossThreadFlagsOffset = reinterpret_cast< PSHORT >( pPsIsThreadTerminating + 0x2 )[ 0 ];

	/*
		mov     rax, [rcx+510h]
		retn
	*/
	m_UniqueThreadIdOffset = reinterpret_cast< PSHORT >( pPsGetThreadId + 0x3 )[ 0 ];

	/*
		test    dword ptr [rax+74h], 200000h
	*/
	/*
		mov     eax, [rcx+74h]  ; IoIsSystemThread
		shr     eax, 0Ah
		and     al, 1
		retn
	*/
	m_MiscFlagsOffset = reinterpret_cast< PBYTE >( pPsIsSystemThread + 0x2 )[ 0 ];

	/*
		This is different <win10 but seems pretty stable nowadays
		TODO: Dynamically grab this, NtQueryInformationThread ThreadSuspendCount works I guess
	*/
	m_ThreadSuspendCountOffset = 0x284;
}

VOID ObjectDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	if ( Driver->IsConnected ) {
		ResolveOffsets( Driver );

		if ( !m_ThreadListHeadOffset || !m_CrossThreadFlagsOffset || !m_UniqueThreadIdOffset )
			return;

		auto Head = Driver->Read64( Process->EProcess + m_ThreadListHeadOffset );
		auto Current = Driver->Read64( Head );

		while ( Current && Current != Head ) {
			/*
				struct _LIST_ENTRY ThreadListEntry;                                     //0x578
				struct _EX_RUNDOWN_REF RundownProtect;                                  //0x588
				struct _EX_PUSH_LOCK ThreadLock;                                        //0x590
				ULONG ReadClusterSize;                                                  //0x598
				volatile ULONG MmLockOrdering;                                          //0x59c
				union
				{
					ULONG CrossThreadFlags;                                             //0x5a0

				This is only temporary, TODO: Fix this
			*/
			auto EThread = Current - ( m_CrossThreadFlagsOffset - 0x28 );

			auto CrossThreadFlags = 
				Driver->Read32( EThread + m_CrossThreadFlagsOffset );
			auto MiscFlags =
				Driver->Read32( EThread + m_MiscFlagsOffset );

			auto ThreadSuspendCount = 
				Driver->Read32( EThread + m_ThreadSuspendCountOffset ) & 0xFF;
			auto UniqueThreadId =
				Driver->Read32( EThread + m_UniqueThreadIdOffset );


			if ( !UniqueThreadId )
				goto Next;

			/*
				if ( (*(_DWORD *)(v4 + 116) & 0x200000) == 0 )
					sub_1409BA290(v4, 0i64);

				 ULONG BypassProcessFreeze:1;                                    //0x74
			*/
			if ( MiscFlags & 0x200000 )
				m_ReportData.Populate( ReportValue {
					std::format( "Thread {} has the BypassProcessFreeze KThread::MiscFlag set!", UniqueThreadId ),
					EReportSeverity::Severe,
					EReportFlags::AvoidDebugging
				} );

			/*
				NtQueryInformationThread ThreadSuspendCount (0x23)
			*/
			if ( ThreadSuspendCount == std::numeric_limits< char >::max( ) ) 
				m_ReportData.Populate( ReportValue {
					std::format( "Thread {}'s KThread::SuspendCount is the maximum!", UniqueThreadId ),
					EReportSeverity::Severe,
					EReportFlags::AvoidDebugging
				} );

			/*
				ULONG Terminated:1;                                             //0x5a0
				ULONG ThreadInserted:1;                                         //0x5a0
				ULONG HideFromDebugger:1;                                       //0x5a0
			*/
			if ( CrossThreadFlags & ( 1 << 2 ) )
				m_ReportData.Populate( ReportValue {
					std::format( "Thread {} has the ThreadHideFromDebugger EThread::CrossThreadFlag set!", UniqueThreadId ),
					EReportSeverity::Severe,
					EReportFlags::AvoidDebugging
				} );

		Next:
			Current = Driver->Read64( Current );
		}
	}

	PROCESS_BASIC_INFORMATION pbi { };
	if ( !Process->Query(
		ProcessBasicInformation,
		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) ) return;

	std::unordered_set< std::string > AlreadySeenDevices {};

ForEachHandle( [ & ] ( const std::wstring& TypeName, const HANDLE& Handle, const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& HandleInfo ) {
	if ( TypeName == L"Job" && Process->IsProcessInJob( Handle ) ) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli {};
		if ( !NT_SUCCESS( NtQueryInformationJobObject(
			Handle,
			( JOBOBJECTINFOCLASS )JobObjectExtendedLimitInformation,
			&jeli, sizeof( jeli ),
			NULL
		) ) ) 
			return;

		if ( jeli.BasicLimitInformation.LimitFlags == JOB_OBJECT_LIMIT_PROCESS_MEMORY )
			m_ReportData.Populate( ReportValue {
				"Possible niche anti-code injection technique detected ( jeli.BasicLimitInformation.LimitFlags == JOB_OBJECT_LIMIT_PROCESS_MEMORY )",

				EReportSeverity::Critical,
				EReportFlags::AvoidCodeInjection
			} );
	}

	if ( TypeName == L"Section" && HandleInfo.UniqueProcessId == pbi.UniqueProcessId ) {
		SECTION_BASIC_INFORMATION sbi {};
		if ( !NT_SUCCESS( NtQuerySection(
			Handle,
			SectionBasicInformation,

			&sbi, sizeof( sbi ),
			NULL
		) ) )
			return;

		if ( sbi.MaximumSize.QuadPart > 268435456LL )
			m_ReportData.Populate( ReportValue {
				"Possible niche anti-memory inspection technique detected ( sbi.MaximumSize.QuadPart > 256MB )",

				EReportSeverity::Critical,
				EReportFlags::AvoidVMQuerying
			} );
	}

	if ( TypeName == L"File" && HandleInfo.UniqueProcessId == pbi.UniqueProcessId ) {
		IO_STATUS_BLOCK iosb {};
		FILE_FS_DEVICE_INFORMATION ffdi {};

		if ( !NT_SUCCESS( NtQueryVolumeInformationFile(
			Handle,

			&iosb,
			&ffdi, sizeof( ffdi ),
			FileFsDeviceInformation
		) ) )
			return;

		if ( ffdi.DeviceType != FILE_DEVICE_UNKNOWN )
			return;

		/*
			Filtering idea: Priority
		*/

		auto Buffer = QueryObject< POBJECT_NAME_INFORMATION >(
			ObjectNameInformation,
			Handle
		);
		if ( !Buffer ) return;

		std::string NameString = UnicodeToString( Buffer->Name );
		if ( AlreadySeenDevices.count( NameString ) )
			return;

		AlreadySeenDevices.insert( NameString );

		m_ReportData.Populate( ReportValue {
			std::format( "Device: {}", NameString ),

			EReportSeverity::Information
		} );
	}
} );
}
}