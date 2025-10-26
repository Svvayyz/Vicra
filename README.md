# Vicra

Vicra is a C++ toolkit designed to flawlessly detect advanced security measures and anti-tampering mechanisms in Windows software. It is intended for use by reverse engineers, security researchers, and developers who need to analyze how processes defend against code injection, debugging, and memory inspection.

## Purpose

Vicra aims to provide automated, extensible detection of Windows process security features and mitigation policies. The toolkit can help identify:

- Techniques that prevent code injection or dynamic code execution
- Process-level memory protection and inspection countermeasures
- Anti-debugging mechanisms
- Callback-based hooks and notification lists

## Usage

```
Source-x64.exe <ProcessName>
```
