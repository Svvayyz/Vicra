#pragma once

namespace Vicra {
class Driver final {
public:
	Driver( ) { }

public:
	/*
		A helper function for finding EProcess - https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS
	*/
	const DWORD64 FindProcess( const DWORD& UniqueProcessId );

public:
	const DWORD Read32( const DWORD64& Address );
	const DWORD64 Read64( const DWORD64& Address );

public:
	const BOOL Setup( );
	const BOOL Close( );

public:
	PBYTE NtosKrnl = NULL;
	PBYTE KernelBase[ 1 ] = { NULL };

	BOOL IsConnected = FALSE;

private:
	PBYTE m_pPsInitialSystemProcess = NULL;

	SHORT m_UniqueProcessIdOffset = NULL;
	SHORT m_ActiveProcessLinksOffset = NULL;

private:
	HANDLE m_Device = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK m_StatusBlock {};
};
}