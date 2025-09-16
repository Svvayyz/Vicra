#include "../Header.h"

namespace Vicra {
void CallbackDetection::Run( const std::shared_ptr< IProcess >& Process ) {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici { };
	if ( Process->Query(
		ProcessInstrumentationCallback,

		&pici,
		sizeof( pici )
	) ) 
		m_ReportData.Populate( ReportValue {
		"NT_SUCCESS( NtQueryProcessInformation( ProcessInstrumentationCallback, ... ) )",
			"https://blog.xenoscr.net/2022/01/17/x86-Nirvana-Hooks.html",

			EReportSeverity::SEVERE,
			EReportFlags::AVOID_VM_INJECTION
		} );

	// return Process->Memory->PEB.ProcessUsingVEH;
	m_ReportData.Populate( ReportValue {
		"Process->Memory->PEB.ProcessUsingVEH",
		"https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection",

		EReportSeverity::SEVERE,
		EReportFlags::AVOID_VM_PROTECT
	} );

	// TODO: reading veh's
	// TODO: ldrregisterdllnotification
}
}