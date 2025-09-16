#pragma once

namespace Vicra {
enum class EReportFlags : USHORT {
	AVOID_NONE = NULL,

	AVOID_VM_QUERY = ( 1 << 1 ),
	AVOID_VM_PROTECT = ( 1 << 2 ),
	AVOID_VM_INJECTION = ( 1 << 3 )
};
enum class EReportSeverity {
	INFO,
	SEVERE,
	CRITICAL
};

class ReportValue {
public:
	ReportValue(
		const std::string& Reason,
		const std::string& URL,

		const EReportSeverity Severity = EReportSeverity::INFO,
		const EReportFlags Flags = EReportFlags::AVOID_NONE
	) : Reason( Reason ), URL( URL ), Severity( Severity ), Flags( Flags ) { };

public:
	const std::string Reason;
	const std::string URL;

	const EReportFlags Flags;
	const EReportSeverity Severity;

public:
	const std::string FormatSeverity( ) const {
		switch ( Severity ) {
		case EReportSeverity::INFO: return MSG_INFO;
		case EReportSeverity::SEVERE: return MSG_SEVERE;
		case EReportSeverity::CRITICAL: return MSG_CRITICAL;
		default: return "UKNOWN";
		}
	}
	const std::string Format( ) const {
		return std::format( 
			"{}{} ( method: {} )",   

			FormatSeverity( ),
			Reason,
			URL
		);
	}
};

class ReportData {
private:
	std::vector< ReportValue > m_Values;

public:
	const std::vector< ReportValue >& GetValues( ) const { return m_Values; }
	const void Populate( const ReportValue ReportValue ) { m_Values.emplace_back( ReportValue ); }

	const BOOL HasAnyReports( ) const {
		return m_Values.size( ) > 0;
	}
};
}