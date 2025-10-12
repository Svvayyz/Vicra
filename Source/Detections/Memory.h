#pragma once

namespace Vicra {
class MemoryDetection : public IPlugin {
private:
	std::unordered_map<SHORT, LPCSTR> m_SystemCallNumberMappings {};

private:
	VOID CreateSCNMappings( );

public:
	VOID Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) override;
};
}
