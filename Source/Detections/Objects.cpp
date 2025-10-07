#include "../Header.h"

namespace Vicra {
void ObjectDetection::ForEachHandle( HandlerFunction Handler ) {
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

void ObjectDetection::Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) {
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