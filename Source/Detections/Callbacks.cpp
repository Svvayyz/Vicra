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
void CallbackDetection::Run( const std::shared_ptr< IProcess >& Process ) {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici { };
	if ( Process->Query(
		ProcessInstrumentationCallback,

		&pici,
		sizeof( pici )
	) ) 
		m_ReportData.Populate( ReportValue {
			"Instrumentation callback",
			"NT_SUCCESS( NtQueryProcessInformation( ProcessInstrumentationCallback, ... ) )",
			"https://blog.xenoscr.net/2022/01/17/x86-Nirvana-Hooks.html",

			EReportSeverity::Severe,
			EReportFlags::AvoidCodeInjection
		} );

	// RtlAddVectoredExceptionHandler( );

	auto& Memory = Process->GetMemory( );

	static const HMODULE hNtDll = GetModuleHandleA( "ntdll.dll" );

	static const auto pLdrRegisterDllNotification = reinterpret_cast< decltype( LdrRegisterDllNotification )* >( 
		GetProcAddress( hNtDll, "LdrRegisterDllNotification" ) 
	);
	static const auto pLdrUnregisterDllNotification = reinterpret_cast< decltype( LdrUnregisterDllNotification )* >(
		GetProcAddress( hNtDll, "LdrUnregisterDllNotification" )
	);

	// Get the LdrDllNotificationList Head's Address
	PLDR_DLL_NOTIFICATION_ENTRY Cookie;
	if ( NT_SUCCESS( pLdrRegisterDllNotification(
		NULL,
		DummyCallback,
		NULL,
		( PVOID* ) &Cookie
	) ) ) {
		auto Head = Cookie->List.Flink;

		LDR_DLL_NOTIFICATION_ENTRY Entry {};
		Memory->Read(
			Head,
			&Entry,
			sizeof( LDR_DLL_NOTIFICATION_ENTRY )
		);

		pLdrUnregisterDllNotification( Cookie );

		if ( Head != Entry.List.Flink || Head != Entry.List.Blink ) 
			m_ReportData.Populate( ReportValue {
				"LdrDllNotificationList isn't empty.....",
				"Head != Entry.List.Flink || Head != Entry.List.Blink",
				"https://elis531989.medium.com/green-with-evil-analyzing-the-new-lockbit-4-green-7f5783c4414c",

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );
	}

	// FiveM's anti-cheat adhesive used to place "call traps" on certain functions using intel's ice2 instr
	// when you called it it instantly threw an error that went straight to adhesive.dll@VectoredExceptionHandler
	// the handler captured the stack and checked if it came from an unknown module, if it did it flagged the person
	// afaik nowadays it only uses it for catching primitive pattern scanners that try to read PAGE_GUARD memory
	// and also software breakpoint detection
	
	auto v = ( PVECTXCPT_CALLOUT_ENTRY )RtlAddVectoredExceptionHandler(
		FALSE,
		DummyVEHCallback
	);

	std::cout << (PVOID)v->VectoredHandler == (PVOID)DummyVEHCallback;

	if ( Process->ExecutableBlock.ProcessUsingVEH )
		m_ReportData.Populate( ReportValue {
			"VectoredExceptionHandlerList isn't empty....",
			"peb.ProcessUsingVEH",
			"https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection",

			EReportSeverity::Information,
			EReportFlags::AvoidVMProtection
		} );

	

	// TODO: TLS Callbacks
	// TODO: Window Callbacks (peb.KernelCallbackTable)
}
}