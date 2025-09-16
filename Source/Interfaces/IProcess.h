#pragma once

namespace Vicra {
class IProcessMemory {
public:
	virtual const BOOL Read(
		const PVOID pAddress,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) = 0;
};

class IProcess {
public:
	virtual const BOOL Attach( const DWORD ProcessId, const ACCESS_MASK DesiredAccess ) = 0;
	virtual const BOOL AttachByName( 
		const std::wstring& ProcessName,

		const ACCESS_MASK DesiredAccess 
	) = 0;
	virtual const BOOL Close( ) = 0;

	virtual const BOOL Query(
		const PROCESSINFOCLASS Class,

		const PVOID pProcessInformation,
		const SIZE_T nProcessInformationLength
	) = 0;

	virtual std::shared_ptr< IProcessMemory >& GetMemory( ) = 0;
};
}