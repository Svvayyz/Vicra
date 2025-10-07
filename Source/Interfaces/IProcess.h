#pragma once

namespace Vicra {
class IProcessMemory {
public:
	virtual const BOOL Read(
		const PVOID pAddress,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) = 0;

	virtual const BOOL Query(
		const PVOID pAddress,

		const MEMORY_INFORMATION_CLASS Class,

		const PVOID pBuffer,
		const SIZE_T nBytesToRead
	) = 0;

	virtual const std::string ToString(
		const PVOID pAddress
	) = 0;
};

class IProcess {
public:
	virtual void Setup( ) = 0;
	virtual void Close( ) = 0;

	virtual const BOOL Attach( const DWORD ProcessId, const ACCESS_MASK DesiredAccess ) = 0;
	virtual const BOOL AttachByName( 
		const std::wstring& ProcessName,

		const ACCESS_MASK DesiredAccess 
	) = 0;
	virtual const BOOL AttachMaxPrivileges( const std::wstring& ProcessName ) = 0;

	virtual const BOOL Query(
		const PROCESSINFOCLASS Class,

		const PVOID pProcessInformation,
		const SIZE_T nProcessInformationLength
	) = 0;
	virtual const ACCESS_MASK QueryAccessMask( ) = 0;

	virtual std::shared_ptr< IProcessMemory >& GetMemory( ) = 0;

public:
	virtual const PVOID DecodePointer( const PVOID Pointer ) = 0;

public:
	virtual const HANDLE DuplicateHandle( const HANDLE& Value ) = 0;
	virtual const BOOL IsProcessInJob( const HANDLE& Job ) = 0;

public:
	ULONG Cookie;
};
}