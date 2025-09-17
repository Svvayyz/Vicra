#pragma once

namespace Vicra {
enum class EReportFlags : USHORT {
	None = NULL,

	AvoidVMQuerying = ( 1 << 1 ),
	AvoidVMProtection = ( 1 << 2 ),
	AvoidCodeInjection = ( 1 << 3 ),
	AvoidDebugging = ( 1 << 4 )
};
enum class EReportSeverity {
	Information,
	Severe,
	Critical
};

class ReportValue {
public:
	ReportValue(
		const std::string& Message,
		const std::string& Reason,
		const std::string& URL,

		const EReportSeverity Severity = EReportSeverity::Information,
		const EReportFlags Flags = EReportFlags::None
	) : Message( Message ), Reason( Reason ), URL( URL ), Severity( Severity ), Flags( Flags ) { };

public:
	const std::string Message;
	const std::string Reason;
	const std::string URL;

	const EReportFlags Flags;
	const EReportSeverity Severity;

public:
	const std::string FormatSeverity( ) const {
		switch ( Severity ) {
		case EReportSeverity::Information: return MSG_INFO;
		case EReportSeverity::Severe: return MSG_SEVERE;
		case EReportSeverity::Critical: return MSG_CRITICAL;
		default: return "UKNOWN";
		}
	}
	const std::string Format( ) const {
		return std::format( 
			"{}{} ( Reason: {}, Method: {} )",   

			FormatSeverity( ),
			Message,

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