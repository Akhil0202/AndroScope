#!/usr/bin/env python3
import argparse
import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET

import manifest_check
import strings_check
import crypto_check

#hiiiii

def decompile_apk(apk_path, output_dir):
    """
    Decompile the APK using Apktool.
    """
    command = f'apktool d "{apk_path}" -o "{output_dir}" -f'
    try:
        subprocess.run(
            command,
            check=True,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"APK decompiled successfully into {output_dir}")
    except subprocess.CalledProcessError as e:
        print("Error during APK decompilation:")
        print(e.stderr.decode())
        exit(1)
    except subprocess.TimeoutExpired:
        print("Decompilation timed out.")
        exit(1)

def get_app_package_prefix(manifest_path):
    """
    Extracts the package name from AndroidManifest.xml and converts it to a directory path format.
    For example, 'com.example.myapp' becomes 'com/example/myapp'.
    """
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.attrib.get("package")
        if package_name:
            return package_name.replace('.', '/')
    except Exception as e:
        print("Error extracting package prefix from manifest:", e)
    return None

def display_menu():
    """
    Display the main menu and return the user's choice.
    """
    print("\nSelect vulnerability checks to perform:")
    print("1. Strings Check")
    print("2. Manifest Check")
    print("3. Crypto & Signature Check")
    print("4. Run All Checks")
    print("5. Exit")
    return input("Enter your choice (1-5): ")

def main():
    parser = argparse.ArgumentParser(
        description="APK Vulnerability Scanner with Modular Checks"
    )
    parser.add_argument("apk", help="Path to the APK file")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        decompile_output_dir = os.path.join(temp_dir, "decompiled_app")
        print("Decompiling APK...")
        decompile_apk(args.apk, decompile_output_dir)

        # Define paths to common files
        manifest_path = os.path.join(decompile_output_dir, "AndroidManifest.xml")
        strings_xml_path = os.path.join(decompile_output_dir, "res", "values", "strings.xml")
        smali_dir = os.path.join(decompile_output_dir, "smali")

        # Automatically extract app package prefix from AndroidManifest.xml
        app_package_prefix = None
        if os.path.exists(manifest_path):
            app_package_prefix = get_app_package_prefix(manifest_path)
            if app_package_prefix:
                print(f"App package prefix (for filtering): {app_package_prefix}")
            else:
                print("Unable to extract package prefix from manifest; proceeding without filtering.")
        else:
            print("Error: AndroidManifest.xml not found in the decompiled APK structure.")

        while True:
            choice = display_menu()
            if choice == "1":
                if os.path.exists(strings_xml_path):
                    strings_check.scan_strings_xml(strings_xml_path)
                else:
                    print("Error: strings.xml file not found.")
            elif choice == "2":
                if os.path.exists(manifest_path):
                    manifest_check.analyze_manifest(manifest_path)
                else:
                    print("Error: AndroidManifest.xml not found.")
            elif choice == "3":
                if os.path.exists(smali_dir):
                    crypto_check.analyze_crypto(smali_dir, app_package_prefix)
                else:
                    print("Error: smali directory not found.")
                crypto_check.check_apk_signing(args.apk)
            elif choice == "4":
                if os.path.exists(strings_xml_path):
                    strings_check.scan_strings_xml(strings_xml_path)
                else:
                    print("Error: strings.xml file not found.")
                if os.path.exists(manifest_path):
                    manifest_check.analyze_manifest(manifest_path)
                else:
                    print("Error: AndroidManifest.xml not found.")
                if os.path.exists(smali_dir):
                    crypto_check.analyze_crypto(smali_dir, app_package_prefix)
                else:
                    print("Error: smali directory not found.")
                crypto_check.check_apk_signing(args.apk)
            elif choice == "5":
                print("Exiting vulnerability scanner.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
