Private API Vulnerability Research: User Information Lookup via Phone Number
Disclaimer: This vulnerability has been responsibly disclosed and patched. This repository contains technical details for educational purposes only.

📖 Project Overview
This research documents the discovery and reverse engineering of a critical private API vulnerability in a major social application that allowed unauthorized user information lookup through phone number enumeration.

🎯 Vulnerability Summary
Vulnerability: Unauthorized User Information Disclosure

Attack Vector: Phone Number Enumeration via Private API

Impact: Exposure of sensitive user data (names, profile info, associated accounts)

Status: Responsibly disclosed and patched

🔧 Technical Methodology
1. Runtime Instrumentation with Frida
Dynamic analysis using custom Frida scripts to intercept application communications:

javascript
Java.perform(function() {
    var Socket = Java.use("java.net.Socket");
    
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        console.log("[+] Socket connection to: " + host + ":" + port);
        send({type: 'socket_connection', host: host, port: port});
        return this.$init(host, port);
    };
});
2. Low-Level Network Interception
Hooking system calls to capture raw network traffic:

javascript
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter: function(args) {
        this.fd = args[0];
        this.buffer = args[1];
        this.length = args[2].toInt32();
        
        if (this.length > 0) {
            var data = this.buffer.readByteArray(this.length);
            send({type: 'raw_send', data: Array.from(new Uint8Array(data))});
        }
    }
});
3. Custom TCP Protocol Discovery
Key Findings:

Non-HTTP custom binary protocol

Raw TCP connections to dedicated servers

Proprietary serialization format

No transport-layer encryption

4. Binary Protocol Reverse Engineering
Decoded packet structure:

text
[4 bytes - Magic Header] [0xDEADBEEF]
[4 bytes - Packet Length]
[2 bytes - Command ID]
[4 bytes - Sequence Number]
[Variable - Payload Data]
[2 bytes - CRC Checksum]
💻 Python Client Implementation
Complete replication of the proprietary protocol:

python
import socket
import struct
import hashlib
from typing import Dict, Any

class SocialAppClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.sequence_number = 0
        self.MAGIC_HEADER = b'\xde\xad\xbe\xef'
    
    def connect(self):
        """Establish TCP connection to the backend server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
    
    def create_lookup_request(self, phone_number: str) -> bytes:
        """Create binary lookup request for phone number"""
        # Protocol implementation
        pass
    
    def parse_response(self, data: bytes) -> Dict[str, Any]:
        """Parse binary response into structured data"""
        # Response parsing logic
        pass
🛡️ Security Impact
Data Exposure: User profiles, names, and associated account information

Privacy Violation: Mass enumeration capabilities

Attack Scale: Could affect millions of users

Detection Bypass: Non-standard protocol evaded traditional security monitoring

🔒 Mitigation Recommendations
API Authentication: Implement proper authentication for all endpoints

Rate Limiting: Prevent mass enumeration attacks

Protocol Security: Use standard encrypted protocols (HTTPS/TLS)

Input Validation: Strict validation for lookup functionalities

Monitoring: Detect unusual lookup patterns
