#pragma once

namespace Vicra {
class MemoryDetection : public IPlugin {
public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}
