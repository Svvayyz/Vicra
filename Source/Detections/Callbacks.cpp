#include "../Header.h"

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
	LIST_ENTRY                     List;
	PLDR_DLL_NOTIFICATION_FUNCTION Callback;
	PVOID                          Context;
} LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY Links;
	PVOID reserved[ 2 ];
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

namespace Vicra {
VOID CallbackDetection::NtDllResolver( ) {
	auto FindListHead = [ ] ( const HMODULE& NtDll, const PLIST_ENTRY Entry ) -> PVOID {
		auto Base = ( PBYTE )( NtDll );

		auto DosHeader = ( PIMAGE_DOS_HEADER )( Base );
		auto NtHeader = ( PIMAGE_NT_HEADERS )( Base + DosHeader->e_lfanew );

		auto Section = IMAGE_FIRST_SECTION( NtHeader );
		for ( WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, Section++ ) {
			if ( strncmp( ( const char* )Section->Name, ".data", IMAGE_SIZEOF_SHORT_NAME ) == 0 )
				break;
		}

		auto MinAddress = ( PVOID )( Base + Section->VirtualAddress );
		auto MaxAddress = ( PVOID )( Base + Section->VirtualAddress + Section->Misc.VirtualSize );

		auto Next = Entry->Flink;

		while ( Next != Entry ) {
			if ( Next >= MinAddress && Next <= MaxAddress )
				return Next;

			Next = Next->Flink;
		}

		return Next;
	};

	using LdrRegisterDllNotification_t = decltype( &LdrRegisterDllNotification );
	using LdrUnregisterDllNotification_t = decltype( &LdrUnregisterDllNotification );

	UNICODE_STRING NtDllName {};

	ANSI_STRING LdrRegDllNotificationName {};
	ANSI_STRING LdrUnregDllNotificationName {};

	HMODULE NtDll;

	LdrRegisterDllNotification_t pLdrRegisterDllNotification;
	LdrUnregisterDllNotification_t pLdrUnregisterDllNotification;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );
	
	RtlInitAnsiString( &LdrRegDllNotificationName, "LdrRegisterDllNotification" );
	RtlInitAnsiString( &LdrUnregDllNotificationName, "LdrUnregisterDllNotification" );

	if ( !NT_SUCCESS( LdrGetDllHandle( 
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll 
	) ) ) return;

	if ( !NT_SUCCESS( LdrGetProcedureAddress( 
		NtDll, &LdrRegDllNotificationName,
		NULL, ( PPVOID ) & pLdrRegisterDllNotification 
	) ) ) return;
	if ( !NT_SUCCESS( LdrGetProcedureAddress(
		NtDll, &LdrUnregDllNotificationName,
		NULL, ( PPVOID )&pLdrUnregisterDllNotification
	) ) ) return;

	PLIST_ENTRY LdrCookie;
	PLIST_ENTRY VehCookie;

	if ( NT_SUCCESS(
		pLdrRegisterDllNotification(
			NULL,
			DummyCallback,
			NULL,
			( PPVOID )&LdrCookie
		)
	) ) m_LdrpDllNotificationList = FindListHead( NtDll, LdrCookie );

	pLdrUnregisterDllNotification( LdrCookie );

	/*
		This needs improvement
	*/
	if ( 
		VehCookie = ( PLIST_ENTRY )( RtlAddVectoredExceptionHandler( NULL, &DummyExceptionCallback ) )
	) m_LdrpVectoredExceptionHandlerList = FindListHead( NtDll, VehCookie->Blink );

	RtlRemoveVectoredExceptionHandler( VehCookie );
	
	if (
		VehCookie = ( PLIST_ENTRY )( RtlAddVectoredContinueHandler( NULL, &DummyExceptionCallback ) )
	) m_LdrpVectoredContinueHandlerList = FindListHead( NtDll, VehCookie->Blink );

	RtlRemoveVectoredContinueHandler( VehCookie );
}

VOID CallbackDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	auto& Memory = Process->GetMemory( );

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici { };
	if ( Process->Query(
		ProcessInstrumentationCallback,

		&pici,
		sizeof( pici )
	) ) 
		m_ReportData.Populate( ReportValue {
			std::format( "Instrumentation callback @ {}", Memory->ToString( pici.Callback ) ),

			EReportSeverity::Severe, 
			EReportFlags::AvoidCodeInjection
		} );

	NtDllResolver( );

	if ( Verdict & ( USHORT )EReportFlags::AvoidVMReading )
		return;

	/*
		TODO: Make a function for this to avoid repetitive code
	*/
	if ( m_LdrpDllNotificationList ) {
		auto Current = m_LdrpDllNotificationList;

		do {
			LDR_DLL_NOTIFICATION_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( LDR_DLL_NOTIFICATION_ENTRY )
			) ) break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( !Memory->Query(
				Entry.Callback,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) goto NextLdrNotification;

			if ( !( mbi.Protect & PAGE_EXECUTABLE ) )
				goto NextLdrNotification;

			m_ReportData.Populate( ReportValue {
				"LdrDllNotificationList @ ntdll entry: " + Memory->ToString( Entry.Callback ),

				EReportSeverity::Severe, 
				EReportFlags::AvoidCodeInjection
			} );

		NextLdrNotification:
			Current = Entry.List.Flink;
		} while ( Current != m_LdrpDllNotificationList );
	}

	if ( m_LdrpVectoredExceptionHandlerList ) {
		auto Current = m_LdrpVectoredExceptionHandlerList;

		do {
			VECTXCPT_CALLOUT_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( VECTXCPT_CALLOUT_ENTRY )
			) )
				break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( Memory->Query(
				Entry.VectoredHandler,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) ) 
				goto NextVectoredExceptionHandler;

			m_ReportData.Populate( ReportValue {
				std::format( "LdrpVectoredExceptionHandlerList @ ntdll entry: {}", Memory->ToString( Process->DecodePointer( Entry.VectoredHandler ) ) ),

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );

		NextVectoredExceptionHandler:
			Current = Entry.Links.Flink;
		} while ( Current != m_LdrpVectoredExceptionHandlerList );
	}
	if ( m_LdrpVectoredContinueHandlerList ) {
		auto Current = m_LdrpVectoredContinueHandlerList;

		do {
			VECTXCPT_CALLOUT_ENTRY Entry {};
			if ( !Memory->Read(
				Current,
				&Entry,
				sizeof( VECTXCPT_CALLOUT_ENTRY )
			) )
				break;

			MEMORY_BASIC_INFORMATION mbi {};
			if ( Memory->Query(
				Entry.VectoredHandler,
				MemoryBasicInformation,
				&mbi, sizeof( MEMORY_BASIC_INFORMATION )
			) )
				goto NextVectoredContinueHandler;

			m_ReportData.Populate( ReportValue {
				std::format( "LdrpVectoredContinueHandlerList @ ntdll entry: {}", Memory->ToString( Process->DecodePointer( Entry.VectoredHandler ) ) ),

				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
			} );

		NextVectoredContinueHandler:
			Current = Entry.Links.Flink;
		} while ( Current != m_LdrpVectoredContinueHandlerList );
	}

	PROCESS_BASIC_INFORMATION pbi {};
	if ( !Process->Query(
		ProcessBasicInformation,
		&pbi,
		sizeof( PROCESS_BASIC_INFORMATION )
	) ) return;

	PEB Peb {};
	if ( !Memory->Read(
		pbi.PebBaseAddress,
		&Peb,
		sizeof( PEB )
	) ) return;

	PEB_LDR_DATA Ldr {};
	if ( !Memory->Read(
		Peb.Ldr,
		&Ldr,
		sizeof( PEB_LDR_DATA )
	) ) return;

	PLIST_ENTRY RemoteHead = reinterpret_cast< PLIST_ENTRY >(
		reinterpret_cast< PBYTE >( Peb.Ldr ) + offsetof( PEB_LDR_DATA, InLoadOrderModuleList )
	);

	PLIST_ENTRY Head = &Ldr.InLoadOrderModuleList;
	PLIST_ENTRY Current = Head->Flink;

	struct Module
	{
		PBYTE Base;
		PBYTE End;

		IMAGE_NT_HEADERS NtHeader;
	};

	std::unordered_map<std::string, std::unordered_map<WORD, std::string>> NameByOrdinalMap;
	std::unordered_map< std::string, Module > Modules = {};

	/*
		this needs improvement
	*/
	std::unordered_set< PBYTE > ExportAddressesSet;

	while ( Current != RemoteHead )
	{
		auto EntryAddress =
			reinterpret_cast< DWORD64 >( Current ) -
			offsetof( LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		LDR_DATA_TABLE_ENTRY Entry {};
		if ( !Memory->Read(
			reinterpret_cast< PVOID >( EntryAddress ),
			&Entry,
			sizeof( LDR_DATA_TABLE_ENTRY )
		) ) break;

		std::vector< BYTE > Buffer( Entry.BaseDllName.Length );
		if ( !Memory->Read(
			Entry.BaseDllName.Buffer,
			Buffer.data( ),
			Entry.BaseDllName.Length
		) ) break;

		Current = Entry.InLoadOrderLinks.Flink;

		IMAGE_DOS_HEADER DosHeader {};
		if ( !Memory->Read(
			Entry.DllBase,
			&DosHeader,
			sizeof( IMAGE_DOS_HEADER )
		) ) continue;

		if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
			continue;

		auto ModuleBase = reinterpret_cast< PBYTE >( Entry.DllBase );

		IMAGE_NT_HEADERS NtHeader {};
		if ( !Memory->Read(
			ModuleBase + DosHeader.e_lfanew,
			&NtHeader,
			sizeof( IMAGE_NT_HEADERS )
		) ) continue;

		if ( NtHeader.Signature != IMAGE_NT_SIGNATURE )
			continue;

		auto WideModuleName = std::wstring(
			reinterpret_cast< LPCWSTR >( Buffer.data() ),
			Entry.BaseDllName.Length / sizeof( WCHAR )
		);
		auto ModuleName = std::string(
			WideModuleName.begin(),
			WideModuleName.end( )
		);

		std::transform( 
			ModuleName.begin( ), 
			ModuleName.end( ), 
			ModuleName.begin( ), 
			[ ]( unsigned char c ) { 
				return std::tolower( c ); 
			} 
		);

		if ( ModuleName == "ntoskrnl.exe" )
		{
			/*
				don't check this lol
			*/

			continue;
		}

		auto ModuleStart = ModuleBase;
		auto ModuleEnd = ModuleBase + NtHeader.OptionalHeader.SizeOfImage;

		auto& TlsDirectory = NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
		if ( TlsDirectory.Size > 0 && TlsDirectory.VirtualAddress > 0 )
		{
			IMAGE_TLS_DIRECTORY Tls {};
			if ( !Memory->Read(
				ModuleBase + TlsDirectory.VirtualAddress,
				&Tls,
				sizeof( IMAGE_TLS_DIRECTORY )
			) ) continue;

			if ( !Tls.AddressOfCallBacks )
				continue;

			auto CallbackArray = Tls.AddressOfCallBacks;

			while ( true )
			{
				PVOID CallbackAddress = NULL;
				if ( !Memory->Read(
					reinterpret_cast< PVOID >( CallbackArray ),
					&CallbackAddress,
					sizeof( DWORD64 )
				) ) break;

				if ( CallbackAddress == 0 )
					break;

				m_ReportData.Populate( ReportValue {
					std::format( "TLS Callback @ {}", Memory->ToString( CallbackAddress ) ),

					EReportSeverity::Severe,
					EReportFlags::AvoidCodeInjection
				} );

				/*
					we don't neccessarily need more results
				*/

				break;

				CallbackArray += sizeof( ULONGLONG );
			}
		}

		/*
			EAT Hooks
		*/
		auto& ExportDirectory = NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
		if ( ExportDirectory.Size > 0 && ExportDirectory.VirtualAddress > 0 )
		{
			IMAGE_EXPORT_DIRECTORY Export {};
			if ( !Memory->Read(
				ModuleBase + ExportDirectory.VirtualAddress,
				&Export,
				sizeof( IMAGE_EXPORT_DIRECTORY )
			) ) continue;

			std::vector< DWORD > NamesBuffer( Export.NumberOfNames );
			std::vector< DWORD > FunctionBuffer( Export.NumberOfFunctions );
			std::vector< WORD > OrdinalBuffer( Export.NumberOfNames );

			Memory->Read( ModuleBase + Export.AddressOfNames, NamesBuffer.data( ), Export.NumberOfNames * sizeof( DWORD ) );
			Memory->Read( ModuleBase + Export.AddressOfFunctions, FunctionBuffer.data( ), Export.NumberOfFunctions * sizeof( DWORD ) );
			Memory->Read( ModuleBase + Export.AddressOfNameOrdinals, OrdinalBuffer.data( ), Export.NumberOfNames * sizeof( WORD ) );

			for ( DWORD i = 0; i < Export.NumberOfNames; i++ )
			{
				WORD Ordinal = OrdinalBuffer[ i ];

				DWORD FunctionRVA = FunctionBuffer[ Ordinal ];
				PBYTE Destination = ModuleBase + FunctionRVA;

				PBYTE OriginalDestination = Destination;

				ExportAddressesSet.insert( Destination );

				BYTE Buffer[ 32 ];
				if ( Memory->Read(
					Destination,
					Buffer,
					sizeof( Buffer )
				) )
				{
					/*for ( int Offset = 0; Offset < sizeof( Buffer ); Offset++ )
					{
						INT InstructionLength = 0;

						hde64s hs;
						if ( ( InstructionLength = hde64_disasm( Buffer + Offset, &hs ) ) == 0 )
							continue;

						if ( hs.opcode == 0xC2 || hs.opcode == 0xC3 )
							break;

						if ( hs.opcode == 0xE9 || hs.opcode == 0xE8 )
						{
							Destination = Destination + Offset + InstructionLength + hs.imm.imm32;
						}
					}*/

					/*
						call/jmp 
					*/
					if ( Buffer[ 0 ] == 0xE9 )
					{
						Destination = Destination + 5 + *reinterpret_cast< INT32* >( Buffer + 1 );
					}
				}

				char NameBuffer[ 256 ];
				Memory->Read( ModuleBase + NamesBuffer[ i ], NameBuffer, sizeof( NameBuffer ) - 1 );

				if ( Destination < ModuleStart || Destination > ModuleEnd )
				{
					m_ReportData.Populate( ReportValue {
						std::format( "Export: {}!{} appears to be hooked (points to: {})", ModuleName, NameBuffer, Memory->ToString( Destination ) ),
						EReportSeverity::Severe,
						EReportFlags::AvoidCodeInjection
					} );
				}
				else
				{
					NameByOrdinalMap[ ModuleName ][ Ordinal ] = NameBuffer;
				}
			}
		}

		Modules[ ModuleName ] = Module {
			ModuleBase,
			ModuleEnd,

			NtHeader
		};
	} 

	for ( auto& [ModuleName, Module] : Modules )
	{
		auto& ImportDirectory = Module.NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

		if ( ImportDirectory.Size < 1 || ImportDirectory.VirtualAddress < 1 )
		{
			continue;
		}

		DWORD ImportDescriptorRva = ImportDirectory.VirtualAddress;
		
		while ( true )
		{
			IMAGE_IMPORT_DESCRIPTOR Import {};
			if ( !Memory->Read(
				Module.Base + ImportDescriptorRva,
				&Import,
				sizeof( IMAGE_IMPORT_DESCRIPTOR )
			) ) break;

			if ( Import.Name == 0 || Import.FirstThunk == 0 )
			{
				break;
			}

			CHAR ImportedModuleNameBuffer[ 256 ] = { 0 };
			if ( !Memory->Read( Module.Base + Import.Name, ImportedModuleNameBuffer, sizeof( ImportedModuleNameBuffer ) - 1 ) )
			{
				break;
			}

			std::string ImportedModuleName = ImportedModuleNameBuffer;
			std::transform(
				ImportedModuleName.begin( ),
				ImportedModuleName.end( ),
				ImportedModuleName.begin( ),
				[ ]( unsigned char c ) {
					return std::tolower( c );
				}
			);

			if ( Modules.find( ImportedModuleName ) != Modules.end( ) )
			{
				auto& ImportedModule = Modules[ ImportedModuleName ];
				auto& OrdinalNames = NameByOrdinalMap[ ImportedModuleName ];

				auto& ExportDirectory = ImportedModule.NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				DWORD ThunkRva = Import.OriginalFirstThunk ? Import.OriginalFirstThunk : Import.FirstThunk;
				DWORD IATRva = Import.FirstThunk;

				while ( true )
				{
					IMAGE_THUNK_DATA Thunk {};
					IMAGE_THUNK_DATA IATThunk {};

					if ( !Memory->Read( Module.Base + ThunkRva, &Thunk, sizeof( IMAGE_THUNK_DATA ) ) ) break;
					if ( !Memory->Read( Module.Base + IATRva, &IATThunk, sizeof( IMAGE_THUNK_DATA ) ) ) break;

					if ( Thunk.u1.AddressOfData == 0 ) break;

					std::string FunctionName;

					if ( IMAGE_SNAP_BY_ORDINAL( Thunk.u1.Ordinal ) )
					{
						WORD Ordinal = IMAGE_ORDINAL( Thunk.u1.Ordinal );

						if ( OrdinalNames.find( Ordinal ) != OrdinalNames.end( ) )
						{
							FunctionName = OrdinalNames[ Ordinal ];
						}
						else
						{
							FunctionName = std::format( "Ordinal #{}", Ordinal );
						}
					}
					else
					{
						CHAR FunctionNameBuffer[ 256 ] = { 0 };
						Memory->Read( Module.Base + Thunk.u1.AddressOfData + sizeof( WORD ), FunctionNameBuffer, sizeof( FunctionNameBuffer ) - 1 );

						FunctionName = FunctionNameBuffer;
					}

					PBYTE Address = reinterpret_cast< PBYTE >( IATThunk.u1.Function );

					
					if ( ExportAddressesSet.find( Address ) == ExportAddressesSet.end( ) )
					{
						if ( Address < ImportedModule.Base || Address > ImportedModule.End )
						{
							m_ReportData.Populate( ReportValue {
								std::format( "Import: {}!{} @ {} appears to be hooked (points to: {})", ImportedModuleName, FunctionName, ModuleName, Memory->ToString( Address ) ),
								EReportSeverity::Severe,
								EReportFlags::AvoidCodeInjection
							} );
						}
					}

					ThunkRva += sizeof( IMAGE_THUNK_DATA );
					IATRva += sizeof( IMAGE_THUNK_DATA );
				}
			}

			ImportDescriptorRva += sizeof( IMAGE_IMPORT_DESCRIPTOR );
		}
	}

	// TODO: Window Callbacks
}
}