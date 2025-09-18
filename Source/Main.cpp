#include "Header.h"

int wmain( int argc, const wchar_t** argv ) {
	if ( argc == 1 )
		argv[ 1 ] = L"firefox.exe";

	auto Process = std::make_shared< Vicra::Process >( );
	if ( !Process->AttachMaxPrivileges( argv[ 1 ] ) ) {
		return 0;
	}
	
	Process->Setup( );
	{
		Vicra::PluginManager Manager { };

		Manager.RegisterPlugin( std::make_shared< Vicra::PolicyDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::MemoryDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::ObjectDetection >( ) );
		Manager.RegisterPlugin( std::make_shared< Vicra::CallbackDetection >( ) );

		Manager.RunAll( Process );
	}
	Process->Close( );
}