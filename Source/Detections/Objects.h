#pragma once

namespace Vicra {
class ObjectDetection : public IPlugin {
public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}