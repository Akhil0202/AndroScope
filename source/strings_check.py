import xml.etree.ElementTree as ET

def is_credential_tag(resource_name):
    """
    Determines if a resource name likely represents a credential.
    Flags names containing 'api_key', 'secret', 'token', or 'username'.
    For 'password', excludes entries that appear to be UI-related or vector paths.
    """
    resource_name_lower = resource_name.lower()
    if any(keyword in resource_name_lower for keyword in ['api_key', 'secret', 'token', 'username', 'firebase']):
        return True
    if 'password' in resource_name_lower:
        if resource_name_lower.startswith('path_'):
            return False
        if 'toggle' in resource_name_lower or 'content_description' in resource_name_lower:
            return False
        return True
    return False

def scan_strings_xml(strings_xml_path):
    """
    Parse strings.xml and scan for potential hardcoded credentials by examining
    the resource names (tag names) rather than their values.
    """
    try:
        tree = ET.parse(strings_xml_path)
        root = tree.getroot()
    except Exception as e:
        print("Error parsing strings.xml:", e)
        return

    vulnerabilities_found = False
    print("\nScanning strings.xml for potential hardcoded credentials (based on tag names):")
    for string in root.findall('string'):
        resource_name = string.attrib.get('name', '')
        if resource_name and is_credential_tag(resource_name):
            vulnerabilities_found = True
            print(f"  - Potential issue in '{resource_name}': {string.text}")
    if not vulnerabilities_found:
        print("No hardcoded credentials found in strings.xml.")
