#pragma once

namespace Vicra {
class IPlugin {
public:
	virtual void Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) = 0;

protected:
	ReportData m_ReportData { };

public:
	const ReportData& GetReportData( ) const { return m_ReportData; };
};
}
