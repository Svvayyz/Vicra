#include "../Header.h"

namespace Vicra {
VOID PolicyDetection::Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) {
	PS_PROTECTION pp {};
	if ( Process->Query(
		ProcessProtectionInformation,

		&pp,
		sizeof( PS_PROTECTION )
	) && pp.Level != PsProtectedTypeNone ) 
		m_ReportData.Populate( ReportValue {
			"Process protection detected (pp.Level != PsProtectedTypeNone)",

			EReportSeverity::Information
		} );

	PROCESS_MITIGATION_POLICY_INFORMATION ppi { };
	ppi.Policy = ProcessSignaturePolicy;

	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && ( ppi.SignaturePolicy.StoreSignedOnly || ppi.SignaturePolicy.MicrosoftSignedOnly ) ) 
		m_ReportData.Populate( ReportValue {
			"Loader image signature enforcement detected (ppi.SignaturePolicy.StoreSignedOnly || ppi.SignaturePolicy.MicrosoftSignedOnly)",

			EReportSeverity::Information,
			EReportFlags::AvoidCodeInjection
		} );
		
	ppi.Policy = ProcessUserShadowStackPolicy;
		
	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && (
		ppi.UserShadowStackPolicy.EnableUserShadowStack || ppi.UserShadowStackPolicy.EnableUserShadowStackStrictMode
	) ) 
		m_ReportData.Populate( ReportValue {
			"Possible stack-walking detected (ppi.UserShadowStackPolicy.EnableUserShadowStack || ppi.UserShadowStackPolicy.EnableUserShadowStackStrictMode)",

			EReportSeverity::Severe,
			EReportFlags::AvoidCodeInjection
		} );

	ppi.Policy = ProcessDynamicCodePolicy;

	if ( Process->Query(
		ProcessMitigationPolicy,

		&ppi,
		sizeof( PROCESS_MITIGATION_POLICY_INFORMATION )
	) && ppi.DynamicCodePolicy.ProhibitDynamicCode ) 
		m_ReportData.Populate( ReportValue {
			"Executable memory allocation prevention detected (ppi.DynamicCodePolicy.ProhibitDynamicCode)",

			EReportSeverity::Information,
			EReportFlags::AvoidCodeInjection
		} );

	
		PROCESS_BASIC_INFORMATION pbi{};
		if (Process->Query(ProcessBasicInformation, &pbi, sizeof(pbi))) {
			auto& M = Process->GetMemory();
			BYTE dbg{};
			if (M->Read((PBYTE)pbi.PebBaseAddress + offsetof(PEB, BeingDebugged), &dbg, sizeof(dbg)) && dbg)
				m_ReportData.Populate(ReportValue{ "PEB.BeingDebugged is set", EReportSeverity::Severe, EReportFlags::AvoidDebugging });

			ULONG ntgf{};
			if (M->Read((PBYTE)pbi.PebBaseAddress + offsetof(PEB, NtGlobalFlag), &ntgf, sizeof(ntgf)) && (ntgf & 0x70))
				m_ReportData.Populate(ReportValue{ "NtGlobalFlag debug bits set", EReportSeverity::Severe, EReportFlags::AvoidDebugging });
		}

		using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
		auto pNtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
		if (pNtSetInformationThread) {
			if (NT_SUCCESS(pNtSetInformationThread(GetCurrentThread(), (THREAD_INFORMATION_CLASS)0x11, nullptr, 0)))
				m_ReportData.Populate(ReportValue{ "NtSetInformationThread(ThreadHideFromDebugger) succeeded", EReportSeverity::Information, EReportFlags::AvoidDebugging });
		}
	

}
}