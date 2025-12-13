
import zipfile
import re
from .utils import AnalysisResult

# Mapping permissions to risk scores
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 5,
    "android.permission.RECEIVE_SMS": 4,
    "android.permission.READ_SMS": 4,
    "android.permission.READ_CONTACTS": 3,
    "android.permission.RECORD_AUDIO": 3,
    "android.permission.CAMERA": 3,
    "android.permission.ACCESS_FINE_LOCATION": 2,
    "android.permission.SYSTEM_ALERT_WINDOW": 4, # Overlay attacks
    "android.permission.INSTALL_PACKAGES": 5,
    "android.permission.READ_PHONE_STATE": 2, # IMEI access
}

def analyze_apk(file_path: str, result: AnalysisResult) -> AnalysisResult:
    try:
        # APKs are just ZIP files
        with zipfile.ZipFile(file_path, 'r') as z:
            # Check for AndroidManifest.xml
            if 'AndroidManifest.xml' not in z.namelist():
                result.add_finding("Invalid APK: No AndroidManifest.xml found", 1)
                return result
            
            # Read Manifest
            # Note: real APK manifests are binary XML. 
            # For this MVP, we use a simple heuristic: 
            # Permissions often appear in plain text or simple encoding even in binary XML 
            # if we grep safely. If not, we'd need a binary parser like `androguard`.
            # To be robust without heavy deps, we scan the raw bytes for the permission strings.
            
            manifest_data = z.read('AndroidManifest.xml')
            
            # Simple string scraping for permissions from binary data
            # This works surprisingly often because the strings are pooled.
            content_str = str(manifest_data) # wildly inefficient but works for searching specific strings
            
            permissions_found = []
            
            for perm, score in DANGEROUS_PERMISSIONS.items():
                if perm.encode('utf-8') in manifest_data: # Search bytes directly
                    result.add_finding(f"Dangerous Permission request: {perm}", score)
                    permissions_found.append(perm)
                    
            result.metadata["permissions_count"] = len(permissions_found)
            
            # Check for reasonable classes.dex
            if 'classes.dex' in z.namelist():
                 result.metadata["has_dex"] = True
            else:
                 result.add_finding("Suspicious: No classes.dex found (no code?)", 2)

            # Extract full file list
            result.metadata["file_structure"] = z.namelist()


    except zipfile.BadZipFile:
        result.add_finding("File is not a valid ZIP/APK archive", 1)
    except Exception as e:
        result.add_finding(f"Error analyzing APK: {str(e)}", 1)
        
    return result
