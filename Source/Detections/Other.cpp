#include "../Header.h"

namespace Vicra {
void EventTracingBypassDetection::Run( const std::shared_ptr< IProcess >& Process ) {
		PROCESS_READWRITEVM_LOGGING_INFORMATION prli {};
		if ( !Process->Query(
			ProcessEnableReadWriteVmLogging,

			&prli,
			sizeof( prli )
		) ) return;

		if ( !prli.EnableReadVmLogging )
			m_ReportData.Populate( ReportValue {
				"!prli.EnableReadVmLogging",
				"https://www.riskinsight-wavestone.com/en/2023/10/a-universal-edr-bypass-built-in-windows-10/"
				} );

		if ( !prli.EnableWriteVmLogging )
			m_ReportData.Populate( ReportValue {
				"!prli.EnableWriteVmLogging",
				"https://www.riskinsight-wavestone.com/en/2023/10/a-universal-edr-bypass-built-in-windows-10/"
				} );
	}
}