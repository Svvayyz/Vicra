#pragma once

namespace Vicra {
class ProcessMemory final {
public:
	ProcessMemory( const HANDLE& Handle ) : m_Handle( Handle ) { };

public:
	const BOOL Read(
		const PVOID pAddress,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	);

	const BOOL Query(
		const PVOID pAddress,

		const MEMORY_INFORMATION_CLASS Class,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	);

	const std::string ToString(
		const PVOID pAddress
	);

private:
	const HANDLE& m_Handle;
};

class Process final {
public:
	Process( ) {
		m_Memory = std::make_shared< ProcessMemory >( m_Handle );
	}

public:
	void Setup( );
	void Close( );

	const BOOL Attach( 
		const DWORD ProcessId, 

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION 
	);
	const BOOL AttachByName(
		const std::wstring& ProcessName,

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION
	);
	const BOOL AttachMaxPrivileges( const std::wstring& ProcessName );

	const BOOL Query(
		const PROCESSINFOCLASS Class,

		const PVOID pProcessInformation,
		const SIZE_T nProcessInformationLength
	);
	const ACCESS_MASK QueryAccessMask( );

	std::shared_ptr< ProcessMemory >& GetMemory( ) { return m_Memory; }

public:
	const PVOID DecodePointer( const PVOID Pointer );

public:
	const HANDLE DuplicateHandle( const HANDLE& Value );
	const BOOL IsProcessInJob( const HANDLE& Job );

	const DWORD GetProcessId( ) {
		return ::GetProcessId( m_Handle );
	}

private:
	HANDLE m_Handle = INVALID_HANDLE_VALUE;

private:
	std::shared_ptr< ProcessMemory > m_Memory;

public:
	DWORD64 EProcess = NULL;
	ULONG Cookie = NULL;
};
}
