# AndroScope
AndroScope is an android vulnerability assessment tool that can find plenty of vulnerabilities present in the android app.

Currently, it finds the following vulnerabilities:
  - Any hardcoded secrets, firebase URL, or API key present in srtings.xml.
  - Lists permissions present in the APK's manifest file and lists all the exported components.
  - Checks if the app has implemented any weak cryptographic or hashing algorithm like DES, XOR, MD5, or SHA1 just to name a few.
  - Analyzes if the app is signed using V1 or V2.

Expanding the vulnerabilities list slowly.
