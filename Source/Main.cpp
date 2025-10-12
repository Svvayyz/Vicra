#include "Header.h"

int wmain( int argc, const wchar_t** argv ) {
	auto Driver = std::make_shared< Vicra::Driver >( );

	auto Process = std::make_shared< Vicra::Process >( );
	if ( !Process->AttachMaxPrivileges( argv[ 1 ] ) ) {
		return 0;
	}
	
	Driver->Setup( );
	Process->Setup( );
	{
		if ( Driver->IsConnected )
			Process->EProcess = Driver->FindProcess( Process->GetProcessId( ) );

		Vicra::PluginManager Manager { };

		Manager.RegisterPlugin( std::make_shared< Vicra::PolicyDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::ObjectDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::MemoryDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::CallbackDetection >( ) );

		Manager.RunAll( Process, Driver );
	}
	Process->Close( );
	Driver->Close( );
}