#pragma once

namespace Vicra {
class PolicyDetection : public IPlugin {
public:
	VOID Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) override;
};
}