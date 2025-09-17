#pragma once

namespace Vicra {
class ProcessMemory : public IProcessMemory {
public:
	ProcessMemory( const HANDLE& Handle ) : m_Handle( Handle ) { };

public:
	const BOOL Read(
		const PVOID pAddress,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) override;

private:
	const HANDLE& m_Handle;
};

class Process : public IProcess {
public:
	Process( ) {
		m_Memory = std::make_shared< ProcessMemory >( m_Handle );
	}

public:
	const BOOL Attach( 
		const DWORD ProcessId, 

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION 
	) override;
	const BOOL AttachByName(
		const std::wstring& ProcessName,

		const ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION
	) override;
	const BOOL Close( ) override;

	const BOOL Query(
		const PROCESSINFOCLASS Class,

		const PVOID pProcessInformation,
		const SIZE_T nProcessInformationLength
	) override;
	const ACCESS_MASK QueryAccessMask( ) override;

	std::shared_ptr< IProcessMemory >& GetMemory( ) override { return m_Memory; }

private:
	HANDLE m_Handle = INVALID_HANDLE_VALUE;

private:
	std::shared_ptr< IProcessMemory > m_Memory;
};
}
