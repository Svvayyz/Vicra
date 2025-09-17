#pragma once

namespace Vicra {
class CallbackDetection : public IPlugin {
private:
	static VOID CALLBACK DummyCallback( ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context )
	{
		return;
	}

public:
	VOID Run( const std::shared_ptr< IProcess >& Process ) override;
};
}