#include "../Header.h"

#include <hde64.h>

namespace Vicra {
VOID MemoryDetection::CreateSCNMappings( ) {
	UNICODE_STRING NtDllName {};

	PBYTE NtDll;

	RtlInitUnicodeString( &NtDllName, L"ntdll.dll" );

	if ( !NT_SUCCESS( LdrGetDllHandle(
		NULL, NULL, &NtDllName, ( PPVOID )&NtDll
	) ) ) return;

	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( NtDll );
	const PIMAGE_NT_HEADERS NtHeader = reinterpret_cast< PIMAGE_NT_HEADERS >( NtDll + DosHeader->e_lfanew );

	const IMAGE_DATA_DIRECTORY ExportDirectoryData = 
		NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = 
		reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( NtDll + ExportDirectoryData.VirtualAddress );

	const PDWORD NameRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfNames );
	const PDWORD FunctionRVAs = reinterpret_cast< PDWORD >( NtDll + ExportDirectory->AddressOfFunctions );

	const PWORD Ordinals = reinterpret_cast< PWORD >( NtDll + ExportDirectory->AddressOfNameOrdinals );

	for ( DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i ) {
		const DWORD FunctionRVA = FunctionRVAs[ Ordinals[ i ] ];
		const PBYTE FunctionVA = NtDll + FunctionRVA;

		/*
			TODO: Anything, this is pretty bad.... :sob:
		*/

		if ( reinterpret_cast< PDWORD >( FunctionVA )[ 0 ] != 0xb8d18b4c )
			continue;

		const SHORT SystemCallNumber = reinterpret_cast< PSHORT >( FunctionVA )[ 2 ];
		const LPCSTR Name = reinterpret_cast< LPCSTR >( NtDll + NameRVAs[ i ] );

		m_SystemCallNumberMappings[ SystemCallNumber ] = Name;
	}
}

VOID MemoryDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	if ( !Driver->IsConnected )
		m_ReportData.Populate( ReportValue {
			"The Driver isn't connected, the MemoryDetection output might be incorrect!"
		} );

	if ( Driver->IsConnected ) {
		/*
			TODO: 
				Even though the offset is the same on EVERY single version of windows (from xp to 24h2)
				Disassembling KeAttachProcess, searching for the 2nd call (KiAttachProcess), and then for 
				movzx   eax, byte ptr [r10+28h]
				would be more future-proof
		*/
		if ( Driver->Read64( Process->EProcess + m_DirectoryTableBaseOffset ) & 0xFFFF000000000000ULL ) {
			m_ReportData.Populate( ReportValue {
				"The (reserved) upper 16 bits of KProcess::DirectoryTableBase are set... Setting them to the CR3 register will result in a #GP exception. Aborting further execution of MemoryDetection.",

				EReportSeverity::Critical,
				EReportFlags::AvoidVMReading
			} );

			return;
		}
	}

	if ( Verdict & ( USHORT ) EReportFlags::AvoidVMQuerying )
		return;

	CreateSCNMappings( );

	SYSTEM_INFO si {};
	MEMORY_BASIC_INFORMATION mbi {};

	GetSystemInfo( &si );

	auto Current = reinterpret_cast< PBYTE >( si.lpMinimumApplicationAddress );
	auto Maximum = reinterpret_cast< PBYTE >( si.lpMaximumApplicationAddress );

	auto& Memory = Process->GetMemory( );
	auto Buffer = std::vector< BYTE >( si.dwPageSize );

	while ( Current < Maximum )
	{
		SHORT SavedSystemCallNumber = 0;

		if ( !Memory->Query(
			Current,
			MemoryBasicInformation,
			&mbi, sizeof( MEMORY_BASIC_INFORMATION )
		) ) {
			Current += si.dwPageSize;

			continue;
		}

		/*
			Direct syscall stub's are usually pretty small... let's not process manually mapped code
		*/
		if ( mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.RegionSize > si.dwPageSize * 10 )
			goto Next;

		if ( !( mbi.Protect & ( PAGE_EXECUTABLE_AND_READABLE ) ) )
			goto Next;

		Buffer.resize( mbi.RegionSize );

		if ( !Memory->Read(
			mbi.BaseAddress,

			Buffer.data( ),
			Buffer.size( )
		) ) 
			goto Next;

		for ( int i = 0; i < Buffer.size( ); i++ ) {
			hde64s hs;
			if ( hde64_disasm( Buffer.data( ) + i, &hs ) == 0 )
				continue;

			/*
				mov eax, scn
			*/
			if ( hs.opcode == 0xB8 )
				SavedSystemCallNumber = hs.imm.imm16;

			/*
				syscall
			*/
			if ( hs.opcode != 0x0F || hs.opcode2 != 0x05 )
				continue;

			std::string Name;

			auto it = m_SystemCallNumberMappings.find( SavedSystemCallNumber );
			if ( it != m_SystemCallNumberMappings.end( ) )
				Name = it->second;
			else
				Name = "Unknown";

			m_ReportData.Populate( ReportValue {
				std::format(
					"Dynamically allocated direct syscall stub ({}) has been detected at {}",

					Name,
					Memory->ToString( reinterpret_cast< PBYTE >( mbi.BaseAddress ) + i )
				),

				EReportSeverity::Severe
			} );
		}

	Next:
		Current += mbi.RegionSize;
	}

	struct L_LIST_ENTRY { PVOID Flink; PVOID Blink; };
	struct L_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
	struct L_PEB_LDR_DATA { ULONG Length; BOOLEAN Initialized; PVOID SsHandle; L_LIST_ENTRY InLoadOrderModuleList; L_LIST_ENTRY InMemoryOrderModuleList; L_LIST_ENTRY InInitializationOrderModuleList; };
	struct L_LDR_DATA_TABLE_ENTRY { L_LIST_ENTRY InLoadOrderLinks; L_LIST_ENTRY InMemoryOrderLinks; L_LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; L_UNICODE_STRING FullDllName; L_UNICODE_STRING BaseDllName; };
	struct L_PEB { BYTE Rsv[0x18]; PVOID Ldr; };

	auto& M = Process->GetMemory();

	HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!localNtdll) localNtdll = LoadLibraryW(L"ntdll.dll");
	if (!localNtdll) return;

	PROCESS_BASIC_INFORMATION pbi{};
	if (!Process->Query(ProcessBasicInformation, &pbi, sizeof(pbi))) return;

	L_PEB peb{};
	if (!M->Read(pbi.PebBaseAddress, &peb, sizeof(peb))) return;

	L_PEB_LDR_DATA ldr{};
	if (!M->Read(peb.Ldr, &ldr, sizeof(ldr))) return;

	PVOID head = ldr.InLoadOrderModuleList.Flink;
	PVOID cur = head;
	PVOID remoteBase = nullptr;

	for (;; ) {
		L_LDR_DATA_TABLE_ENTRY e{};
		if (!M->Read(cur, &e, sizeof(e))) break;

		std::wstring base;
		if (e.BaseDllName.Buffer && e.BaseDllName.Length) {
			base.resize(e.BaseDllName.Length / sizeof(wchar_t));
			M->Read(e.BaseDllName.Buffer, base.data(), e.BaseDllName.Length);
		}

		std::wstring low = base;
		for (auto& ch : low) ch = (wchar_t)towlower(ch);
		if (low == L"ntdll.dll") { remoteBase = e.DllBase; break; }

		cur = e.InLoadOrderLinks.Flink;
		if (!cur || cur == head) break;
	}

	if (!remoteBase) return;

	auto dos = (PIMAGE_DOS_HEADER)localNtdll;
	auto nt = (PIMAGE_NT_HEADERS)((PBYTE)localNtdll + dos->e_lfanew);
	auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto ed = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)localNtdll + dir.VirtualAddress);
	auto names = (PDWORD)((PBYTE)localNtdll + ed->AddressOfNames);
	auto ords = (PWORD)((PBYTE)localNtdll + ed->AddressOfNameOrdinals);
	auto funcs = (PDWORD)((PBYTE)localNtdll + ed->AddressOfFunctions);

	const SIZE_T SZ = 64;
	std::vector<BYTE> lb(SZ), rb(SZ);

	for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
		auto name = (LPCSTR)((PBYTE)localNtdll + names[i]);
		auto rva = funcs[ords[i]];
		auto lfn = (PBYTE)localNtdll + rva;
		auto rfn = (PBYTE)remoteBase + rva;

		if (!ReadProcessMemory(GetCurrentProcess(), lfn, lb.data(), lb.size(), nullptr)) continue;
		if (!M->Read(rfn, rb.data(), rb.size())) continue;

		bool diff = memcmp(lb.data(), rb.data(), lb.size()) != 0;
		bool cc = true; for (size_t k = 0; k < 8 && k < rb.size(); ++k) { if (rb[k] != 0xCC) { cc = false; break; } }
		if (!diff && memcmp(lb.data(), rb.data(), 8) != 0) diff = true;

		if (diff || cc) {
			m_ReportData.Populate(ReportValue{
				std::format("Inline hook detected on ntdll!{} (diff={},cc={})", name, diff ? 1 : 0, cc ? 1 : 0),
				EReportSeverity::Severe,
				EReportFlags::AvoidCodeInjection
				});
		}
	}
}
}
