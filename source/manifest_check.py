import xml.etree.ElementTree as ET

def analyze_manifest(manifest_path):
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception as e:
        print("Error parsing AndroidManifest.xml:", e)
        return

    print("\nAnalyzing AndroidManifest.xml for misconfigurations...\n")

    # Example: Check for overly permissive permissions
    print("List of permission granted:")
    for perm in root.findall('uses-permission'):
        perm_name = perm.attrib.get('{http://schemas.android.com/apk/res/android}name', '')
        print(perm_name)
    for perm in root.findall('uses-permission'):
        perm_name = perm.attrib.get('{http://schemas.android.com/apk/res/android}name', '')
        overly_permissive = ['android.permission.READ_EXTERNAL_STORAGE',
                             'android.permission.WRITE_EXTERNAL_STORAGE',
                             'android.permission.INTERNET',
                             'android.permission.SEND_SMS',
                             'android.permission.READ_SMS',
                             'android.permission.RECIEVE_SMS',
                             'android.permission.READ_CONTACTS',
                             'android.permission.WRITE_CONTACTS',
                             'android.permission.READ_PHONE_STATE',
                             'android.permission.READ_CALL_LOG',
                             'android.permission.WRITE_CALL_LOG',
                             'android.permission.ACCESS_FINE_LOCATION',
                             'android.permission.ACCESS_COARSE_LOCATION',
                             'android.permission.SYSTEM_ALERT_WINDOW',
                             'android.permission.CAMERA',
                             'android.permission.RECORD_AUDIO']
        if perm_name in overly_permissive:
            print(f"\nWarning: Overly permissive permission detected: {perm_name}")

    # Example: Check for exported components
    components = []
    components.extend(root.findall('.//activity'))
    components.extend(root.findall('.//service'))
    components.extend(root.findall('.//receiver'))
    components.extend(root.findall('.//provider'))

    for comp in components:
        comp_name = comp.attrib.get('{http://schemas.android.com/apk/res/android}name', 'unknown')
        exported = comp.attrib.get('{http://schemas.android.com/apk/res/android}exported')
        if exported == "true":
            print(f"Warning: Component '{comp_name}' is exported.")
        elif exported is None:
            print(f"Warning: Component '{comp_name}' is missing the 'android:exported' attribute.")

    # Example: Check for insecure intent filters (this can be expanded with more logic)
    for activity in root.findall('.//activity'):
        intent_filters = activity.findall('intent-filter')
        if intent_filters:
            for i_filter in intent_filters:
                # Custom logic to detect insecure intent filters goes here.
                print(f"Info: Activity '{activity.attrib.get('{http://schemas.android.com/apk/res/android}name', 'unknown')}' has intent filters.")


