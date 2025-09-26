#pragma once

namespace Vicra {
class IPlugin {
public:
	virtual void Initialize( ) { }; // Some plugins will need this some won't  
	virtual void Run( const std::shared_ptr< IProcess >& Process ) = 0;

protected:
	ReportData m_ReportData { };

public:
	const ReportData& GetReportData( ) const { return m_ReportData; };
};
}
