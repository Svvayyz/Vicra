#include "../Header.h"

namespace Vicra {
void MemoryDetection::Run( const std::shared_ptr< IProcess >& Process ) {
	VM_COUNTERS vmc { };
	if ( Process->Query( 
		ProcessVmCounters, 
		
		&vmc, 
		sizeof( VM_COUNTERS ) 
	) && vmc.PagefileUsage > vmc.WorkingSetSize )
		m_ReportData.Populate( ReportValue {
			"Possible niche anti-memory inspection technique detected",
			"vmc.PagefileUsage > vmc.WorkingSetSize",
			"https://secret.club/2021/05/23/big-memory.html",

			EReportSeverity::Critical,
			EReportFlags::AvoidVMQuerying
		} );
}
}
