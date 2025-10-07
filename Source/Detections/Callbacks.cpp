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
void CallbackDetection::NtDllResolver( ) {
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

void CallbackDetection::Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) {
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

			m_ReportData.Populate( ReportValue {
				"LdrDllNotificationList @ ntdll entry: " + Memory->ToString( Entry.Callback ),

				EReportSeverity::Severe, 
				EReportFlags::AvoidCodeInjection
			} );

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

			m_ReportData.Populate( ReportValue {
				std::format( "LdrpVectoredHandlerList @ ntdll entry: {}", Memory->ToString( Process->DecodePointer( Entry.VectoredHandler ) ) ),

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );

			Current = Entry.Links.Flink;
		} while ( Current != m_LdrpVectorHandlerList );
	}

	// TODO: TLS Callbacks
	// TODO: Window Callbacks
}
}