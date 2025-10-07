#pragma once

namespace Vicra {
class MemoryDetection : public IPlugin {
private:
	std::unordered_map<SHORT, LPCSTR> m_SystemCallNumberMappings {};

private:
	void CreateSCNMappings( );

public:
	void Run( const std::shared_ptr< IProcess >& Process, const USHORT& Verdict ) override;
};
}
