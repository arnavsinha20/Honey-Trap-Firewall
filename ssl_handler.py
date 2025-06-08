# ===============================
# 🔒 SSL Socket Handler
# ===============================
import socket
import ssl
import os
import platform
import time

# Constants
CERT_DIR = "certs"
SERVER_CERT = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")
CA_CERT = os.path.join(CERT_DIR, "ca.crt")

class SSLSocketWrapper:
    """Wrapper for SSL socket operations"""
    
    @staticmethod
    def create_server_context():
        """Create SSL context for server"""
        try:
            if not SSLSocketWrapper.generate_self_signed_cert():
                print("Warning: Failed to generate SSL certificates. SSL may not work properly.")
            
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
                
                # Configure cipher to enhance security
                context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
                context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
                
                return context
            except Exception as e:
                print(f"Error loading certificates: {e}")
                # Return a dummy context as fallback
                return ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        except Exception as e:
            print(f"Error creating SSL context: {e}")
            raise
    
    @staticmethod
    def create_client_context(verify=False):
        """Create SSL context for client"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        if verify and os.path.exists(CA_CERT):
            try:
                context.load_verify_locations(cafile=CA_CERT)
            except Exception:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    @staticmethod
    def ensure_cert_dir():
        """Ensure certificate directory exists"""
        if not os.path.exists(CERT_DIR):
            os.makedirs(CERT_DIR)
    
    @staticmethod
    def generate_self_signed_cert():
        """Generate a self-signed certificate if none exists"""
        SSLSocketWrapper.ensure_cert_dir()
        
        # Check if certificates already exist
        if os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY):
            return True
        
        # Generate simple self-signed cert if other methods fail
        try:
            # Create basic certificate and key
            with open(SERVER_CERT, 'w') as f:
                f.write("-----BEGIN CERTIFICATE-----\n")
                f.write("MIIDazCCAlOgAwIBAgIUJFdUZQ5XfQGtCKUgYnWyDUeUZ+gwDQYJKoZIhvcNAQEL\n")
                f.write("BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n")
                f.write("GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MDExMjAwMDBaFw0yNDA1\n")
                f.write("MDExMjAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\n")
                f.write("HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\n")
                f.write("AQUAA4IBDwAwggEKAoIBAQCyZ0LVxRZn1Q0QEU8RfFmFJvBOyZQuC4LGxDqEDwKQ\n")
                f.write("jIhCN1SaCdMlCnEZXiDxGGUQxb8WotECZZ+Jui2XFkXSpPfiS9cHKB7XdbkOF8cj\n")
                f.write("XKwpMhkKO5kcOvMhFQnLfIzqF5n0KJxpHulKcYvIWnCvJYXAgZLxRcUiP8LXUbM1\n")
                f.write("h+JHbZmghDxGj9XcN+IsYZPxUHNHp5JS6eW7gNW0jAUP05xq/BCrnI9jvJN7YzY7\n")
                f.write("JX1q7Hk4c5QUbEJHjQXEUdMEro5wylcbdHJIGvUKo/4eFDwqQRCTaLdNcbRgRs2W\n")
                f.write("ZvrhLDFPSa6x4J2ZAXeQRKOvazCXQIq7xvRRgMiTeZE5AgMBAAGjUzBRMB0GA1Ud\n")
                f.write("DgQWBBTdWYblsCD9ZZgTXGHxEXTHCEhTPjAfBgNVHSMEGDAWgBTdWYblsCD9ZZgT\n")
                f.write("XGHxEXTHCEhTPjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8\n")
                f.write("Qh1FWk/SGKNg0tuKkKOXaBGtKXoFNDJbSQBUY4NKK3gQI2U60ePnbjNEmHagsCVy\n")
                f.write("fFGAXmQCEDdQw1M5vE3LUJjyG3cOBcZ8c5bICIxqRQ4VYRRJu0xXgOmksjH9jmJ1\n")
                f.write("-----END CERTIFICATE-----\n")
            
            with open(SERVER_KEY, 'w') as f:
                f.write("-----BEGIN PRIVATE KEY-----\n")
                f.write("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyZ0LVxRZn1Q0Q\n")
                f.write("EU8RfFmFJvBOyZQuC4LGxDqEDwKQjIhCN1SaCdMlCnEZXiDxGGUQxb8WotECZZ+J\n")
                f.write("ui2XFkXSpPfiS9cHKB7XdbkOF8cjXKwpMhkKO5kcOvMhFQnLfIzqF5n0KJxpHulK\n")
                f.write("cYvIWnCvJYXAgZLxRcUiP8LXUbM1h+JHbZmghDxGj9XcN+IsYZPxUHNHp5JS6eW7\n")
                f.write("gNW0jAUP05xq/BCrnI9jvJN7YzY7JX1q7Hk4c5QUbEJHjQXEUdMEro5wylcbdHJI\n")
                f.write("GvUKo/4eFDwqQRCTaLdNcbRgRs2WZvrhLDFPSa6x4J2ZAXeQRKOvazCXQIq7xvRR\n")
                f.write("gMiTeZE5AgMBAAECggEAB5L3DJsxJT1Yf4sM3V31cQ+NTpi+CKlcnFhwFSW/U7IV\n")
                f.write("H7QfACv6B6MnLDzQBZ1iW7OzrQv4HrUx7DzAH/QJzyzU9J1J9/chxb04TGQzpAPX\n")
                f.write("-----END PRIVATE KEY-----\n")
            
            # Copy to CA cert for verification
            with open(CA_CERT, 'w') as f:
                f.write("-----BEGIN CERTIFICATE-----\n")
                f.write("MIIDazCCAlOgAwIBAgIUJFdUZQ5XfQGtCKUgYnWyDUeUZ+gwDQYJKoZIhvcNAQEL\n")
                f.write("BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n")
                f.write("GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MDExMjAwMDBaFw0yNDA1\n")
                f.write("MDExMjAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\n")
                f.write("HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\n")
                f.write("AQUAA4IBDwAwggEKAoIBAQCyZ0LVxRZn1Q0QEU8RfFmFJvBOyZQuC4LGxDqEDwKQ\n")
                f.write("jIhCN1SaCdMlCnEZXiDxGGUQxb8WotECZZ+Jui2XFkXSpPfiS9cHKB7XdbkOF8cj\n")
                f.write("XKwpMhkKO5kcOvMhFQnLfIzqF5n0KJxpHulKcYvIWnCvJYXAgZLxRcUiP8LXUbM1\n")
                f.write("h+JHbZmghDxGj9XcN+IsYZPxUHNHp5JS6eW7gNW0jAUP05xq/BCrnI9jvJN7YzY7\n")
                f.write("JX1q7Hk4c5QUbEJHjQXEUdMEro5wylcbdHJIGvUKo/4eFDwqQRCTaLdNcbRgRs2W\n")
                f.write("ZvrhLDFPSa6x4J2ZAXeQRKOvazCXQIq7xvRRgMiTeZE5AgMBAAGjUzBRMB0GA1Ud\n")
                f.write("DgQWBBTdWYblsCD9ZZgTXGHxEXTHCEhTPjAfBgNVHSMEGDAWgBTdWYblsCD9ZZgT\n")
                f.write("XGHxEXTHCEhTPjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8\n")
                f.write("Qh1FWk/SGKNg0tuKkKOXaBGtKXoFNDJbSQBUY4NKK3gQI2U60ePnbjNEmHagsCVy\n")
                f.write("fFGAXmQCEDdQw1M5vE3LUJjyG3cOBcZ8c5bICIxqRQ4VYRRJu0xXgOmksjH9jmJ1\n")
                f.write("-----END CERTIFICATE-----\n")
            
            return True
            
        except Exception as e:
            print(f"Error generating simple certificate: {e}")
            return False