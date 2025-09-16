#include "../Header.h"

namespace Vicra {
const BOOL ProcessMemory::Read(
	const PVOID pAddress,

	const PVOID pBuffer,
	const SIZE_T nBytesToRead
) {
	SIZE_T nBytesRead = NULL;
	if ( !NT_SUCCESS( NtReadVirtualMemory(
		m_Handle,

		pAddress,
		pBuffer,
		nBytesToRead,

		&nBytesRead
	) ) ) return FALSE;

	return nBytesRead;
}

const BOOL Process::Attach(
	const DWORD ProcessId,

	const ACCESS_MASK DesiredAccess
) {
	this->Close( );

	static OBJECT_ATTRIBUTES Attributes = { sizeof( Attributes ) };
	static CLIENT_ID ClientId = { };

	ClientId.UniqueProcess = ( HANDLE ) ProcessId;

	return NT_SUCCESS( NtOpenProcess(
		( PHANDLE )&m_Handle,

		DesiredAccess,
		&Attributes,
		&ClientId
	) );
}
const BOOL Process::AttachByName(
	const std::wstring& ProcessName,

	const ACCESS_MASK DesiredAccess
) {
	// convert this to syscalls (NtQuerySystemInformation)

	HANDLE hSnapshot = CreateToolhelp32Snapshot( 
		TH32CS_SNAPPROCESS,
		NULL 
	);
	if ( hSnapshot == INVALID_HANDLE_VALUE ) return FALSE;

	PROCESSENTRY32 Entry {};
	Entry.dwSize = sizeof( PROCESSENTRY32 );

	if ( !Process32First( hSnapshot, &Entry ) ) return FALSE;

	do {
		if ( wcscmp( Entry.szExeFile, ProcessName.c_str( ) ) == 0 )
			break;
	} while ( Process32Next( hSnapshot, &Entry ) );

	return this->Attach( Entry.th32ProcessID, DesiredAccess );
}
const BOOL Process::Close( ) {
	if ( m_Handle == INVALID_HANDLE_VALUE ) return TRUE;
	
	return NT_SUCCESS( NtClose( m_Handle ) );
}

const BOOL Process::Query(
	const PROCESSINFOCLASS Class,

	const PVOID pProcessInformation,
	const SIZE_T nProcessInformationLength
) {
	ULONG ulReturnLength = NULL;

	if ( !NT_SUCCESS( NtQueryInformationProcess(
		m_Handle,

		Class,
		pProcessInformation,
		nProcessInformationLength,

		&ulReturnLength
	) ) ) return FALSE;

	return ulReturnLength == nProcessInformationLength;
}
}