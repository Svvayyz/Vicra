#pragma once

namespace Vicra {
class CallbackDetection : public IPlugin {
private:
	/*
		Dummy callbacks
	*/

	static VOID CALLBACK DummyCallback( ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context )
	{
		return;
	}
	static LONG CALLBACK DummyVEHCallback( PEXCEPTION_POINTERS ExceptionInfo ) {
		return NULL;
	}

private:
	VOID NtDllResolver( );

private:
	PVOID m_LdrpDllNotificationList = NULL;
	PVOID m_LdrpVectorHandlerList = NULL;

public:
	VOID Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) override;
};
}