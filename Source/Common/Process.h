#pragma once

namespace Vicra {
class ProcessMemory final : public IProcessMemory {
public:
	ProcessMemory( const HANDLE& Handle ) : m_Handle( Handle ) { };

public:
	const BOOL Read(
		const PVOID pAddress,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) override;

	const BOOL Query(
		const PVOID pAddress,

		const MEMORY_INFORMATION_CLASS Class,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) override;

	const std::string ToString(
		const PVOID pAddress
	) override;

private:
	const HANDLE& m_Handle;
};

class Process final : public IProcess {
public:
	Process( ) {
		m_Memory = std::make_shared< ProcessMemory >( m_Handle );
	}

public:
	void Setup( ) override;
	void Close( ) override;

	const BOOL Attach( 
		const DWORD ProcessId, 

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION 
	) override;
	const BOOL AttachByName(
		const std::wstring& ProcessName,

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION
	) override;
	const BOOL AttachMaxPrivileges( const std::wstring& ProcessName ) override;

	const BOOL Query(
		const PROCESSINFOCLASS Class,

		const PVOID pProcessInformation,
		const SIZE_T nProcessInformationLength
	) override;
	const ACCESS_MASK QueryAccessMask( ) override;

	std::shared_ptr< IProcessMemory >& GetMemory( ) override { return m_Memory; }

public:
	const PVOID DecodePointer( const PVOID Pointer ) override;

public:
	const HANDLE DuplicateHandle( const HANDLE& Value ) override;
	const BOOL IsProcessInJob( const HANDLE& Job ) override;

private:
	HANDLE m_Handle = INVALID_HANDLE_VALUE;

private:
	std::shared_ptr< IProcessMemory > m_Memory;
};
}
