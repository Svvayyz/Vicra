#pragma once

namespace Vicra {
class PolicyDetection : public IPlugin {
public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}