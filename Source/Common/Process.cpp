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
const BOOL ProcessMemory::Query(
	const PVOID pAddress,

	const MEMORY_INFORMATION_CLASS Class,

	const PVOID pBuffer,
	const SIZE_T nBytesToRead
) {
	return NT_SUCCESS( NtQueryVirtualMemory(
		m_Handle,

		pAddress,
		Class,

		pBuffer,
		nBytesToRead,

		NULL
	) );
}

const std::string ProcessMemory::ToString(
	const PVOID pAddress
) {
	std::stringstream Stream;
	Stream << "0x" << std::hex << reinterpret_cast< uintptr_t >( pAddress );

	char Buffer[ 0x1000 ];
	if ( !Query(
		pAddress,

		MemoryMappedFilenameInformation,
		Buffer,
		sizeof( Buffer )
	) ) {
		Stream << " @ ??";

		return Stream.str( );
	}
		
	auto Unicode = reinterpret_cast< PUNICODE_STRING >( Buffer );

	std::wstring Path( Unicode->Buffer, Unicode->Length / sizeof( WCHAR ) );
	std::wstring wFileName = Path.substr( Path.find_last_of( L"\\/" ) + 1 );

	std::string FileName( wFileName.begin( ), wFileName.end( ) );

	Stream << " @ " << FileName;

	return Stream.str( );
}

void Process::Setup( ) {
	PROCESS_BASIC_INFORMATION pbi { };
	if ( !this->Query(
		ProcessBasicInformation,

		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) ) return;

	this->Query(
		ProcessCookie,
		&Cookie,
		sizeof( ULONG )
	);
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
			return this->Attach( Entry.th32ProcessID, DesiredAccess );
	} while ( Process32Next( hSnapshot, &Entry ) );

	return FALSE;
}
const BOOL Process::AttachMaxPrivileges( const std::wstring& ProcessName ) {
	ACCESS_MASK AccessMask = PROCESS_QUERY_LIMITED_INFORMATION;

	if ( AttachByName( ProcessName, READ_CONTROL ) ) {
		AccessMask = QueryAccessMask( );
		if ( AccessMask == 0 ) AccessMask = REQUIRED_MASK;
	}

	return AttachByName( ProcessName, AccessMask );
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

const PVOID Process::DecodePointer( const PVOID Pointer ) {
	const auto ROL8 = [ ] ( auto value, auto count ) {
		count &= 63;
		return ( value << count ) | ( value >> ( 64 - count ) );
	};

	/*
		__int64 __fastcall RtlDecodePointer(__int64 Pointer)
		{
		  unsigned int Cookie; // edx
		  int NtStatus; // eax
		  unsigned int ProcessCookieBuf; // [rsp+48h] [rbp+10h] BYREF

		  Cookie = g_ProcessCookie;
		  ProcessCookieBuf = 0;
		  if ( !g_ProcessCookie )
		  {
			NtStatus = ZwQueryInformationProcess(-1i64, 36i64, &ProcessCookieBuf);
			if ( NtStatus < 0 )
			  RtlRaiseStatus((unsigned int)NtStatus);
			Cookie = ProcessCookieBuf;
			g_ProcessCookie = ProcessCookieBuf;
		  }
		  return __ROR8__(Pointer, 64 - (Cookie & 0x3F)) ^ Cookie;
		}
	*/

	return ( PVOID )( ROL8( ( ULONGLONG ) Pointer, Cookie & 0x3F ) ^ Cookie );
}

const HANDLE Process::DuplicateHandle( const HANDLE& Value ) {
	HANDLE DuplicatedHandle {};
	if ( !NT_SUCCESS( NtDuplicateObject(
		m_Handle,
		Value,
		NtCurrentProcess( ),
		&DuplicatedHandle,
		NULL,
		NULL,
		DUPLICATE_SAME_ACCESS
	) ) ) return INVALID_HANDLE_VALUE;

	return DuplicatedHandle;
}
const BOOL Process::IsProcessInJob( const HANDLE& Job ) {
	return NT_SUCCESS( NtIsProcessInJob(
		m_Handle,
		Job
	) );
}
}