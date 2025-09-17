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
	return NT_SUCCESS( NtQueryInformationProcess(
		m_Handle,

		Class,
		pProcessInformation,
		nProcessInformationLength,

		NULL
	) );
}
const ACCESS_MASK Process::QueryAccessMask( ) {
	ULONG LengthNeeded = 0;
	NtQuerySecurityObject(
		m_Handle,

		DACL_SECURITY_INFORMATION,
		NULL, NULL,

		&LengthNeeded
	);

	auto pSecurityDescriptor = std::malloc( LengthNeeded );

	if ( !NT_SUCCESS( NtQuerySecurityObject(
		m_Handle,
		DACL_SECURITY_INFORMATION,

		pSecurityDescriptor, LengthNeeded,

		&LengthNeeded
	) ) ) {
		std::free( pSecurityDescriptor );
		
		return NULL;
	}

	PACL pDacl = NULL;
	BOOL DaclPresent, DaclDefaulted = FALSE;
	if ( !GetSecurityDescriptorDacl(
		pSecurityDescriptor,

		&DaclPresent,
		&pDacl,
		&DaclDefaulted
	) ) {
		std::free( pSecurityDescriptor );

		return NULL;
	}
	if ( !DaclPresent ) {
		std::free( pSecurityDescriptor );

		return PROCESS_ALL_ACCESS;
	}

	HANDLE TokenHandle;
	if ( !NT_SUCCESS( NtOpenProcessToken(
		NtCurrentProcess( ),
		TOKEN_QUERY,
		&TokenHandle
	) ) ) {
		std::free( pSecurityDescriptor );

		return NULL;
	}

	GetTokenInformation( 
		TokenHandle, 
		TokenUser, 
		NULL, NULL, 
		&LengthNeeded 
	);

	auto pTokenUser = ( PTOKEN_USER ) std::malloc( LengthNeeded );
	if ( !GetTokenInformation(
		TokenHandle,
		TokenUser,
		pTokenUser,
		LengthNeeded,
		&LengthNeeded
	) ) {
		std::free( pSecurityDescriptor );
		std::free( pTokenUser );

		NtClose( TokenHandle );

		return NULL;
	}

	LengthNeeded = GetLengthSid( pTokenUser->User.Sid );
	
	auto pUserSID = std::malloc( LengthNeeded );
	CopySid( LengthNeeded, pUserSID, pTokenUser->User.Sid );

	std::free( pTokenUser );
	NtClose( TokenHandle );

	ACL_SIZE_INFORMATION AclInfo {};
	if ( !GetAclInformation( 
		pDacl, 
		
		&AclInfo, 
		sizeof( ACL_SIZE_INFORMATION ), 
		AclSizeInformation 
	) ) {
		std::free( pSecurityDescriptor );
		std::free( pUserSID );

		return NULL;
	}

	DWORD AccessMask = NULL;
	for ( int i = 0; i < AclInfo.AceCount; i++ ) {
		PACCESS_ALLOWED_ACE pAce = NULL;
		if ( !GetAce( pDacl, i, ( void** )&pAce ) ) continue;
		if ( !EqualSid( pUserSID, &pAce->SidStart ) ) continue;

		AccessMask |= pAce->Mask;
	}

	std::free( pSecurityDescriptor );
	std::free( pUserSID );

	return AccessMask;
}
}