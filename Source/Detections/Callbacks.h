#pragma once

namespace Vicra {
class CallbackDetection : public IPlugin {
public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}