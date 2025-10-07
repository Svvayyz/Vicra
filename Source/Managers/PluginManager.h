#pragma once

namespace Vicra {
class PluginManager {
private:
	std::vector< std::shared_ptr< IPlugin > > m_Plugins;

public:
	void RegisterPlugin( std::shared_ptr< IPlugin > Plugin ) { m_Plugins.emplace_back( Plugin ); }
	void RunAll( std::shared_ptr< Process >& Process ) {
		USHORT Verdict = 0;

		for ( auto& Plugin : m_Plugins ) {
			Plugin->Run( Process, Verdict );

			auto& ReportData = Plugin->GetReportData( );
			if ( !ReportData.HasAnyReports( ) ) continue;

			auto& Values = ReportData.GetValues( );

			for ( auto& Value : Values ) {
				std::cout << Value.Format( ) << '\n';

				Verdict |= ( USHORT ) Value.Flags;
			}
		}
	}
};
}
