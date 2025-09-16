#include "Header.h"

int main( ) {
	auto Process = std::make_shared< Vicra::Process >( );
	if ( !Process->AttachByName( L"firefox.exe" ) )
		return 0;

	Vicra::PluginManager Manager { };

	Manager.RegisterPlugin( std::make_shared< Vicra::MemoryDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::ObjectDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::CallbackDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::EventTracingBypassDetection >( ) );

	Manager.RunAll( Process );
}