# Vicra

Vicra is a C++ toolkit designed to flawlessly detect advanced security measures and anti-tampering mechanisms in Windows software. It is intended for use by reverse engineers, security researchers, and developers who need to analyze how processes defend against code injection, debugging, and memory inspection.

## Purpose

Vicra aims to provide automated, extensible detection of Windows process security features and mitigation policies. The toolkit can help identify:

- Techniques that prevent code injection or dynamic code execution
- Process-level memory protection and inspection countermeasures
- Anti-debugging mechanisms
- Callback-based hooks and notification lists

## What’s Implemented

- Modular plugin architecture for extensible detection logic
- Detailed reporting system with severity and categorization
- Object, policy, and callback detection modules
- Windows internals-based process and handle inspection
- Support for analyzing both running processes and static process names

## Planned Features

### Kernel-Mode Features

- **ObCallbacks Enumeration:**  
  - Enumerate kernel-mode object callbacks (`ObRegisterCallbacks`) to detect process/thread/image access filtering and anti-tampering mechanisms.
- **Image Load Notifications:**  
  - Detect and enumerate kernel image load notification routines (`PsSetLoadImageNotifyRoutine`) to identify monitoring, anti-injection, and anti-cheat features.
- **Process/Thread Notifications:**  
  - Enumerate process/thread creation and termination notification routines for advanced behavioral monitoring.

### Hook Detection

- **SSDT Hooks:**  
  - Identify System Service Descriptor Table hooks commonly used by rootkits and kernel-mode anti-cheat solutions.
- **Inline Hooks:**  
  - Detect code patching at function entry points in both user-mode and kernel-mode modules.
- **EAT (Export Address Table) Hooks:**  
  - Monitor modifications to exported function pointers for user-mode API redirection.
- **IAT (Import Address Table) Hooks:**  
  - Detect tampering of imported function pointers, commonly used for user-mode API hooking.

### Other Planned Features

- **Improved Reporting:**  
  - Export results to various formats (e.g., JSON, CSV)
- **User Interface:**  
  - Basic CLI or GUI for controlling analysis and viewing results
- **Documentation & Examples:**  
  - Expanded code comments, usage guides, and API documentation
- **Unit Tests & Continuous Integration:**  
  - Automated tests for reliability and maintenance
