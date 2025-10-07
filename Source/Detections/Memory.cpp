#include "../Header.h"

namespace Vicra {
void MemoryDetection::CreateSCNMappings( ) {
	UNICODE_STRING NtDllName {};

	PBYTE NtDll;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );

	if ( !NT_SUCCESS( LdrGetDllHandle(
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll
	) ) ) return;

	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( NtDll );
	const PIMAGE_NT_HEADERS NtHeader = reinterpret_cast< PIMAGE_NT_HEADERS >( NtDll + DosHeader->e_lfanew );

	const IMAGE_DATA_DIRECTORY ExportDirectoryData = 
		NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = 
		reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( NtDll + ExportDirectoryData.VirtualAddress );

	const PDWORD NameRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfNames );
	const PDWORD FunctionRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfFunctions );

	const PWORD Ordinals = reinterpret_cast< PWORD >( NtDll + ExportDirectory->AddressOfNameOrdinals );

	for ( DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i ) {
		const DWORD FunctionRVA = FunctionRVAs[ Ordinals[ i ] ];
		const PBYTE FunctionVA = NtDll + FunctionRVA;

		/*
			TODO: Anything, this is pretty bad.... :sob:
		*/

		if ( reinterpret_cast< PDWORD >( FunctionVA )[ 0 ] != 0xb8d18b4c )
			continue;

		const SHORT SystemCallNumber = reinterpret_cast< PSHORT >( FunctionVA )[ 2 ];
		const LPCSTR Name = reinterpret_cast< LPCSTR >( NtDll + NameRVAs[ i ] );

		m_SystemCallNumberMappings[ SystemCallNumber ] = Name;
	}
}

void MemoryDetection::Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) {
	if ( Verdict & ( USHORT ) EReportFlags::AvoidVMQuerying )
		return;

	CreateSCNMappings( );

	SYSTEM_INFO si {};
	MEMORY_BASIC_INFORMATION mbi {};

	GetSystemInfo( &si );

	auto Current = reinterpret_cast< PBYTE >( si.lpMinimumApplicationAddress );
	auto Maximum = reinterpret_cast< PBYTE >( si.lpMaximumApplicationAddress );

	auto& Memory = Process->GetMemory( );
	auto Buffer = std::vector< BYTE >( si.dwPageSize );

	constexpr BYTE PatternData[ 10 ] = {
		0x4C, 0x8B, 0xD1,			  // mov r10, rcx
		0xB8, 0xCC, 0xCC, 0xCC, 0xCC, // mov eax, wildcard
		0x0F, 0x05					  // syscall
	};
	constexpr SIZE_T SizeOfPattern = sizeof( PatternData );

	while ( Current < Maximum )
	{
		if ( !Memory->Query(
			Current,
			MemoryBasicInformation,
			&mbi, sizeof( MEMORY_BASIC_INFORMATION )
		) ) {
			Current += si.dwPageSize;

			continue;
		}

		if ( mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE )
			goto Next;

		if ( 
			!( mbi.Protect & ( PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ ) ) || 
			mbi.Protect & ( PAGE_GUARD | PAGE_NOACCESS ) 
		)
			goto Next;

		Buffer.resize( mbi.RegionSize );

		if ( !Memory->Read(
			mbi.BaseAddress,

			Buffer.data( ),
			Buffer.size( )
		) ) 
			goto Next;

		for ( int i = 0; i < Buffer.size( ) - SizeOfPattern; i++ )
		{
			bool Found = true;

			for ( int j = 0; j < SizeOfPattern; j++ )
			{
				if ( PatternData[ j ] == 0xCC )
					continue;

				if ( PatternData[ j ] == Buffer.data( )[ i + j ] )
					continue;

				Found = false;

				break;
			}

			if ( !Found )
				continue;

			const SHORT SystemCallNumber = 
				reinterpret_cast< PSHORT >( Buffer.data( ) + i )[ 2 ];

			if ( m_SystemCallNumberMappings.find( SystemCallNumber ) == m_SystemCallNumberMappings.end( ) )
				continue;

			m_ReportData.Populate( ReportValue {
				std::format( 
					"Dynamically allocated direct syscall stub ({}) has been detected at {}", 
					
					m_SystemCallNumberMappings[ SystemCallNumber ],
					Memory->ToString( reinterpret_cast< PBYTE >( mbi.BaseAddress ) + i ) 
				),

				EReportSeverity::Severe
			} );
		}

	Next:
		Current += mbi.RegionSize;
	}
}
}
