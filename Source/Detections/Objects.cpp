#include "../Header.h"

namespace Vicra {
void ObjectDetection::Run( const std::shared_ptr< IProcess >& Process ) {
	if ( !Process->ExecutableBlock.ProcessInJob ) return;

	std::cout << "ProcessIsInJob" << '\n';

	PROCESS_HANDLE_SNAPSHOT_INFORMATION phsi {};
	if ( !Process->Query(
		ProcessHandleInformation,

		&phsi,
		sizeof( phsi )
	) ) return;

	// TODO: iterate through all handles, check if their type == JobType, then check the properties of it....

	/*HANDLE job = nullptr;
	NtCreateJobObject( &job, MAXIMUM_ALLOWED, nullptr );

	NtAssignProcessToJobObject( job, NtCurrentProcess( ) );

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
	limits.ProcessMemoryLimit = 0x1000;
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
	NtSetInformationJobObject( job, JobObjectExtendedLimitInformation,
		&limits, sizeof( limits ) );*/

	// https://secret.club/2021/01/20/diet-process.html
}
}