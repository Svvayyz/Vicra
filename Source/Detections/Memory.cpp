#include "../Header.h"

namespace Vicra {
void MemoryDetection::Run( const std::shared_ptr< IProcess >& Process ) {
	VM_COUNTERS vmc { };
	PROCESS_BASIC_INFORMATION pbi { };

	PEB peb {};

	if ( Process->Query( 
		ProcessVmCounters, 
		
		&vmc, 
		sizeof( VM_COUNTERS ) 
	) && vmc.PagefileUsage > vmc.WorkingSetSize )
		m_ReportData.Populate( ReportValue {
			"vmc.PagefileUsage > vmc.WorkingSetSize",
			"https://secret.club/2021/05/23/big-memory.html",

			EReportSeverity::CRITICAL,
			EReportFlags::AVOID_VM_QUERY
		} );

	if ( !Process->Query(
		ProcessBasicInformation,

		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) ) return;

	auto& Memory = Process->GetMemory( );

	if ( Memory->Read(
		pbi.PebBaseAddress,

		&peb,
		sizeof( PEB )
	) ) return;
}
}
