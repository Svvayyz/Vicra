#include "Header.h"

int wmain( int argc, const wchar_t** argv ) {
	if ( argc == 1 )
		argv[ 1 ] = L"firefox.exe";

	auto Process = std::make_shared< Vicra::Process >( );
	if ( !Process->AttachByName( argv[ 1 ], READ_CONTROL ) ) return 0;
	
	auto AccessMask = Process->QueryAccessMask( );
	if ( AccessMask == 0 ) AccessMask = REQUIRED_MASK;

	if ( !( AccessMask & REQUIRED_MASK ) ) 
		std::cout << MSG_CRITICAL << "Insufficient rights, the scan results might be inaccurate (The process might be using DACL's to restrict access... Or you've launched me without admin perms ;p)" << "\n\n";

	if ( !Process->AttachByName( argv[ 1 ], AccessMask ) ) return 2;
	
	Vicra::PluginManager Manager { };

	Manager.RegisterPlugin( std::make_shared< Vicra::PolicyDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::MemoryDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::ObjectDetection >( ) );
	Manager.RegisterPlugin( std::make_shared< Vicra::CallbackDetection >( ) );

	Manager.RunAll( Process );

	Process->Close( );
}