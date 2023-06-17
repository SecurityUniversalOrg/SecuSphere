

ASSESSMENT_BENCHMARKS = [
    {"Name": "OWASP ASVS v. 3.1", "Description": "", "Version": "3.1"}
]

ASSESSMENT_RULES = [
    {"BanchmarkName": "OWASP ASVS v. 3.1", "Number": "10.1", "Description": "Verify that a path can be built from a trusted CA to each Transport Layer Security (TLS) server certificate, and that each server certificate is valid.", "ImplementationLevels": "1,2,3"},
{"BanchmarkName": "OWASP ASVS v. 3.1", "Number": "10.2", "Description": "Verify that TLS is used for all connections (including both external and backend connections) that are authenticated or that involve sensitive data or functions, and does not fall back to insecure or unencrypted protocols. Ensure the strongest alternative is the preferred algorithm.", "ImplementationLevels": "1,2,3"},
{"BanchmarkName": "OWASP ASVS v. 3.1", "Number": "10.3", "Description": "Verify that backend TLS connection failures are logged.", "ImplementationLevels": "3"},
]