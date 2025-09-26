#pragma once

namespace Vicra {
class ObjectDetection : public IPlugin {
private:
	using HandlerFunction = std::function< void( const std::wstring&, const HANDLE&, const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& ) >;

private:
	std::vector< BYTE > m_DataBuffer {};
	std::vector< BYTE > m_ObjectDataBuffer {};

	std::unordered_map< USHORT, std::wstring > m_NameMappings { };

private:
	/*
		Helper function for NtQuerySystemInformation
	*/
	template< typename T >
	T Query( const SYSTEM_INFORMATION_CLASS Class ) {
		m_DataBuffer.resize( 0x1000 );

		NTSTATUS Status {};
		ULONG BytesRead = 0;

		while ( ( Status = NtQuerySystemInformation(
			Class,

			m_DataBuffer.data( ),
			m_DataBuffer.size( ),

			&BytesRead
		) ) == STATUS_INFO_LENGTH_MISMATCH )
			m_DataBuffer.resize( m_DataBuffer.size( ) * 2 );

		m_DataBuffer.resize( BytesRead );
		if ( !NT_SUCCESS( Status ) ) return NULL;

		return reinterpret_cast< T >( m_DataBuffer.data( ) );
	}

	/*
		Helper function for NtQueryObject
	*/
	template< typename T >
	T QueryObject( const OBJECT_INFORMATION_CLASS Class, const HANDLE& Object ) {
		ULONG ReturnLength = 0;
		NtQueryObject(
			Object,
			ObjectTypeInformation,
			NULL, NULL,
			&ReturnLength
		);

		m_ObjectDataBuffer.resize( ReturnLength );

		if ( !NT_SUCCESS(
			NtQueryObject(
				Object,
				ObjectTypeInformation,
				m_ObjectDataBuffer.data( ),
				ReturnLength,
				nullptr
			) )
		) return NULL;

		return reinterpret_cast< T >( m_ObjectDataBuffer.data( ) );
	}

private:
	void ForEachHandle( HandlerFunction Handler );

public:
	void Run( const std::shared_ptr< IProcess >& Process ) override;
};
}