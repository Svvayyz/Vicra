#include "../Header.h"

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
	LIST_ENTRY                     List;
	PLDR_DLL_NOTIFICATION_FUNCTION Callback;
	PVOID                          Context;
} LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY Links;
	PVOID reserved[ 2 ];
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

namespace Vicra {
VOID CallbackDetection::NtDllResolver( ) {
	auto FindListHead = [ ] ( const HMODULE& NtDll, const PLIST_ENTRY Entry ) -> PVOID {
		auto Base = ( PBYTE )( NtDll );

		auto DosHeader = ( PIMAGE_DOS_HEADER )( Base );
		auto NtHeader = ( PIMAGE_NT_HEADERS )( Base + DosHeader->e_lfanew );

		auto Section = IMAGE_FIRST_SECTION( NtHeader );
		for ( WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, Section++ ) {
			if ( strncmp( ( const char* )Section->Name, ".data", IMAGE_SIZEOF_SHORT_NAME ) == 0 )
				break;
		}

		auto MinAddress = ( PVOID )( Base + Section->VirtualAddress );
		auto MaxAddress = ( PVOID )( Base + Section->VirtualAddress + Section->Misc.VirtualSize );

		auto Next = Entry->Flink;

		while ( Next != Entry ) {
			if ( Next >= MinAddress && Next <= MaxAddress )
				return Next;

			Next = Next->Flink;
		}

		return Next;
	};

	using LdrRegisterDllNotification_t = decltype( &LdrRegisterDllNotification );
	using LdrUnregisterDllNotification_t = decltype( &LdrUnregisterDllNotification );

	UNICODE_STRING NtDllName {};

	ANSI_STRING LdrRegDllNotificationName {};
	ANSI_STRING LdrUnregDllNotificationName {};

	HMODULE NtDll;

	LdrRegisterDllNotification_t pLdrRegisterDllNotification;
	LdrUnregisterDllNotification_t pLdrUnregisterDllNotification;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );
	
	RtlInitAnsiString( &LdrRegDllNotificationName, "LdrRegisterDllNotification" );
	RtlInitAnsiString( &LdrUnregDllNotificationName, "LdrUnregisterDllNotification" );

	if ( !NT_SUCCESS( LdrGetDllHandle( 
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll 
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress( 
		NtDll, &LdrRegDllNotificationName,
		NULL, ( PPVOID ) & pLdrRegisterDllNotification 
	) ) ) return;
	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		NtDll, &LdrUnregDllNotificationName,
		NULL, ( PPVOID )&pLdrUnregisterDllNotification
	) ) ) return;

	PLIST_ENTRY LdrCookie;
	PLIST_ENTRY VehCookie;

	if ( NT_SUCCESS(
		pLdrRegisterDllNotification(
			NULL,
			DummyCallback,
			NULL,
			( PPVOID )&LdrCookie
		)
	) ) m_LdrpDllNotificationList = FindListHead( NtDll, LdrCookie );

	/*
		This needs improvement
	*/
	if ( 
		VehCookie = ( PLIST_ENTRY )( RtlAddVectoredExceptionHandler( NULL, &DummyVEHCallback ) ) 
	) m_LdrpVectorHandlerList = FindListHead( NtDll, VehCookie->Blink );
	

	pLdrUnregisterDllNotification( LdrCookie );
	RtlRemoveVectoredExceptionHandler( VehCookie );
}

VOID CallbackDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	auto& Memory = Process->GetMemory( );

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici { };
	if ( Process->Query(
		ProcessInstrumentationCallback,

		&pici,
		sizeof( pici )
	) ) 
		m_ReportData.Populate( ReportValue {
			std::format( "Instrumentation callback @ {}", Memory->ToString( pici.Callback ) ),

			EReportSeverity::Severe, 
			EReportFlags::AvoidCodeInjection
		} );

	NtDllResolver( );

	if ( Verdict & ( USHORT )EReportFlags::AvoidVMReading )
		return;

	/*
		TODO: Make a function for this to avoid repetitive code
	*/
	if ( m_LdrpDllNotificationList ) {
		auto Current = m_LdrpDllNotificationList;

		do {
			LDR_DLL_NOTIFICATION_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( LDR_DLL_NOTIFICATION_ENTRY )
			) ) break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( !Memory->Query(
				Entry.Callback,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) goto NextLdrNotification;

			if ( !( mbi.Protect & PAGE_EXECUTABLE ) )
				goto NextLdrNotification;

			m_ReportData.Populate( ReportValue {
				"LdrDllNotificationList @ ntdll entry: " + Memory->ToString( Entry.Callback ),

				EReportSeverity::Severe, 
				EReportFlags::AvoidCodeInjection
			} );

		NextLdrNotification:
			Current = Entry.List.Flink;
		} while ( Current != m_LdrpDllNotificationList );
	}
	if ( m_LdrpVectorHandlerList ) {
		auto Current = m_LdrpVectorHandlerList;

		do {
			VECTXCPT_CALLOUT_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( VECTXCPT_CALLOUT_ENTRY )
			) )
				break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( Memory->Query(
				Entry.VectoredHandler,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) 
				goto NextVectoredHandler;

			m_ReportData.Populate( ReportValue {
				std::format( "LdrpVectoredHandlerList @ ntdll entry: {}", Memory->ToString( Process->DecodePointer( Entry.VectoredHandler ) ) ),

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );

		NextVectoredHandler:
			Current = Entry.Links.Flink;
		} while ( Current != m_LdrpVectorHandlerList );
	}

	// TODO: omg tls callbacks hi!!
	
	struct L_LIST_ENTRY { PVOID Flink; PVOID Blink; };
	struct L_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
	struct L_PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; PVOID SsHandle; L_LIST_ENTRY InLoadOrderModuleList; L_LIST_ENTRY InMemoryOrderModuleList; L_LIST_ENTRY InInitializationOrderModuleList; };
	struct L_LDR_DATA_TABLE_ENTRY { L_LIST_ENTRY InLoadOrderLinks; L_LIST_ENTRY InMemoryOrderLinks; L_LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; L_UNICODE_STRING FullDllName; L_UNICODE_STRING BaseDllName; };
	struct L_PEB { BYTE Rsv[0x18]; PVOID Ldr; };

	auto& M = Process->GetMemory();

	PROCESS_BASIC_INFORMATION pbi{};
	if (!Process->Query(ProcessBasicInformation, &pbi, sizeof(pbi))) return;

	L_PEB peb{};
	if (!M->Read(pbi.PebBaseAddress, &peb, sizeof(peb))) return;

	L_PEB_LDR_DATA ldr{};
	if (!M->Read(peb.Ldr, &ldr, sizeof(ldr))) return;

	PVOID head = ldr.InLoadOrderModuleList.Flink;
	PVOID cur = head;

	for (;; ) {
		L_LDR_DATA_TABLE_ENTRY e{};
		if (!M->Read(cur, &e, sizeof(e))) break;

		PVOID modBase = e.DllBase;
		IMAGE_DOS_HEADER dos{};
		if (!M->Read(modBase, &dos, sizeof(dos))) { cur = e.InLoadOrderLinks.Flink; if (!cur || cur == head) break; else continue; }
		IMAGE_NT_HEADERS nt{};
		if (!M->Read((PBYTE)modBase + dos.e_lfanew, &nt, sizeof(nt))) { cur = e.InLoadOrderLinks.Flink; if (!cur || cur == head) break; else continue; }

		auto tlsDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (!tlsDir.VirtualAddress || !tlsDir.Size) { cur = e.InLoadOrderLinks.Flink; if (!cur || cur == head) break; else continue; }

		IMAGE_TLS_DIRECTORY64 tls{};
		if (!M->Read((PBYTE)modBase + tlsDir.VirtualAddress, &tls, sizeof(tls))) { cur = e.InLoadOrderLinks.Flink; if (!cur || cur == head) break; else continue; }

		ULONGLONG list{};
		if (!M->Read((PVOID)tls.AddressOfCallBacks, &list, sizeof(list))) { cur = e.InLoadOrderLinks.Flink; if (!cur || cur == head) break; else continue; }

		ULONGLONG p = list;
		for (;; ) {
			ULONGLONG cb{};
			if (!M->Read((PVOID)p, &cb, sizeof(cb))) break;
			if (!cb) break;

			MEMORY_BASIC_INFORMATION mbi{};
			if (M->Query((PVOID)cb, MemoryBasicInformation, &mbi, sizeof(mbi)) && (mbi.Protect & PAGE_EXECUTE)) {
				std::wstring baseName;
				if (e.BaseDllName.Buffer && e.BaseDllName.Length) {
					baseName.resize(e.BaseDllName.Length / sizeof(wchar_t));
					M->Read(e.BaseDllName.Buffer, baseName.data(), e.BaseDllName.Length);
				}
				std::string baseNameA(baseName.begin(), baseName.end());
				m_ReportData.Populate(ReportValue{
					std::format("TLS callback {} in {}", M->ToString((PVOID)cb), baseNameA),
					EReportSeverity::Information,
					EReportFlags::AvoidCodeInjection
					});
			}
			p += sizeof(ULONGLONG);
		}

		cur = e.InLoadOrderLinks.Flink;
		if (!cur || cur == head) break;
	}
	// TODO: Window Callbacks
}
}