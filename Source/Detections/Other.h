#pragma once

namespace Vicra {
class EventTracingBypassDetection : public IPlugin {
public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}