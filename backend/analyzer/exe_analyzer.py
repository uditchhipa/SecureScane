
import pefile
import os
from .utils import AnalysisResult

DANGEROUS_IMPORTS = {
    # Keylogging
    "GetAsyncKeyState": 3,
    "SetWindowsHookExA": 4,
    "GetKeyboardState": 2,
    
    # Injection / Execution
    "CreateRemoteThread": 5,
    "VirtualAllocEx": 4,
    "WriteProcessMemory": 5,
    "ShellExecuteA": 3,
    "WinExec": 3,
    
    # Network
    "InternetOpenA": 2,
    "URLDownloadToFileA": 4,
    "socket": 2,
    "connect": 2,
    
    # Persistence / Registry
    "RegCreateKeyExA": 3,
    "RegSetValueExA": 3,
}

def analyze_exe(file_path: str, result: AnalysisResult) -> AnalysisResult:
    try:
        print(f"DEBUG: Parsing PE file {file_path}")
        pe = pefile.PE(file_path)
        print("DEBUG: PE file parsed successfully")
    except Exception as e:
        print(f"DEBUG: Failed to parse PE file: {e}")
        # Initialize pe_imports and pe_sections to empty lists even on failure to avoid frontend issues
        result.metadata["pe_imports"] = []
        result.metadata["pe_sections"] = []
        result.add_finding(f"Failed to parse PE header: {str(e)}", 1)
        return result

    # 1. Analyze Imports
    all_imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8').lower()
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        all_imports.append(f"{func_name} ({dll_name})")
                        if func_name in DANGEROUS_IMPORTS:
                            score = DANGEROUS_IMPORTS[func_name]
                            result.add_finding(f"Suspicious API Import: {func_name} (from {dll_name})", score)
            except Exception:
                continue
    result.metadata["pe_imports"] = all_imports

    # 2. Analyze Sections (Entropy check for packing)
    # High entropy (> 7.0) often indicates packed/encrypted code (common in malware)
    all_sections = []
    for section in pe.sections:
        entropy = section.get_entropy()
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        all_sections.append(f"{name} (Entropy: {entropy:.2f})")
        
        # Keep old metadata for backward compat if needed, or just remove
        # result.metadata[f"section_{name}_entropy"] = round(entropy, 2)
        
        if entropy > 7.5:
            result.add_finding(f"High entropy section '{name}' ({round(entropy, 2)}). Possible packed/encrypted code.", 4)
            
    result.metadata["pe_sections"] = all_sections

    # 3. Check for compilation timestamp anomalies (simple check)
    # (Omitted for brevity, but easy to add)
    
    return result
