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
	SHORT m_ThreadListHeadOffset = NULL;
	SHORT m_CrossThreadFlagsOffset = NULL;
	SHORT m_UniqueThreadIdOffset = NULL;

	BYTE m_MiscFlagsOffset = NULL;
	SHORT m_ThreadSuspendCountOffset = NULL;

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
			Class,
			NULL, NULL,
			&ReturnLength
		);

		m_ObjectDataBuffer.resize( ReturnLength );

		if ( !NT_SUCCESS(
			NtQueryObject(
				Object,
				Class,
				m_ObjectDataBuffer.data( ),
				ReturnLength,
				nullptr
			) )
		) return NULL;

		return reinterpret_cast< T >( m_ObjectDataBuffer.data( ) );
	}

	std::string UnicodeToString( const UNICODE_STRING& Unicode ) {
		int Size = WideCharToMultiByte(
			CP_UTF8, NULL,
			Unicode.Buffer,
			Unicode.Length / sizeof( WCHAR ),
			NULL, NULL, NULL, NULL
		);

		std::string String( Size, 0 );
		WideCharToMultiByte(
			CP_UTF8, NULL,
			Unicode.Buffer,
			Unicode.Length / sizeof( WCHAR ),
			String.data( ), Size, NULL, NULL
		);

		return String;
	}

private:
	VOID ForEachHandle( HandlerFunction Handler );
	VOID ResolveOffsets( const std::shared_ptr< Driver >& Driver );

public:
	VOID Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) override;
};
}