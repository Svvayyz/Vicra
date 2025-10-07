#include "../Header.h"

namespace Vicra {
void PolicyDetection::Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) {
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
}
}