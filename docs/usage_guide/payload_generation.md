# Payload Generation

## Payload Generation

See Agents & Stager Guide (on the sidebar) for complete agent type breakdown and usage:

## Payload Staging

NeoC2 supports staging payloads directly through the `payload_upload` base-command of the remote client server, allowing operators to deploy binary executables like .exe, .dll, or other file types in addition to Python scripts. The payload to be staged must be present on the command-and-control-sever and its path provided for staging.

### Capabilities
- **Multi-Format Support**: Upload EXE, DLL, PY, JS, VBS, BAT, PS1, and other binary/script files
- **Encryption**: XOR encryption using SECRET_KEY environment variable with Base64 encoding
- **Automatic Serving**: Uploaded payloads automatically available at `/api/assets/main.js`
- **Intelligent Execution**: Droppers automatically detect payload type and handle appropriately
- **Maximum Size**: Supports payloads up to 50MB
- **Overwrite Functionality**: New uploads replace previous payloads

#### Example Usage:
```
NeocC2 > payload_upload <options>
# Then deploy droppers
NeoC2 > stager generate linux_binary host=<c2_host> port=<c2_port> protocol=https
```