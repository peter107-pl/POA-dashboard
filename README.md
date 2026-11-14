# Limitless Essentials POA – team review

Password-protected weekly snapshot of the POA dashboard, rebuilt every Sunday at 11:45 (Cairo).

The page is encrypted (AES-256-GCM, key derived from the team password with PBKDF2-SHA256, 600,000 rounds) and is only decrypted in the reader's browser. No readable plan data is stored in this repository.

`tools/` holds the builder: `POA_PASSWORD=... python3 tools/poa_build.py POA.xlsx .`
