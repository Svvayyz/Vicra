#pragma once

#include "Includes.h"

#define INLINE inline
#define FORCE_INLINE __forceinline

#define MSG_CRITICAL "\033[42m\033[41m CRITICAL \033[0m "
#define MSG_SEVERE "\033[42m\033[43m SEVERE \033[0m "
#define MSG_INFO "\033[42m\033[30m INFO \033[0m "

#include "Interfaces/IProcess.h"

#include "Common/ReportData.h"
#include "Common/Process.h"

#include "Interfaces/IPlugin.h"

#include "Detections/Memory.h"
#include "Detections/Callbacks.h"
#include "Detections/Objects.h"
#include "Detections/Policies.h"

#include "Managers/PluginManager.h"

#define REQUIRED_MASK PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE