import cryptography.hazmat
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.types
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.x509
import cryptography.x509.oid
from fastapi import FastAPI, Response

import socket
import ssl
import cryptography
import json

import traceback

from OpenSSL import SSL as ossl

### Create FastAPI instance with custom docs and openapi url
app = FastAPI(
    docs_url="/api/py/docs",
    openapi_url="/api/py/openapi.json")

@app.get("/api/py/v1/dumpCerts")
def dump_certs(host: str, port: int = 443):
    result = {
        'version': '1',
        'host': host,
        'port': port,
        'ip': None,
        'certificate_chain': []
    }
    try:
        cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes
        algorithms = {
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey: 'Elliptic Curve',
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: 'RSA'
        }

        chain_der = []
        # requires python 3.13, vercel only supports 3.12 at the time of writing.
#        ctx = ssl.create_default_context()
#
#        with ctx.wrap_socket(socket.create_connection((host, port)), server_hostname=host) as ssock:
#            chain_der += ssock.get_unverified_chain()
#            result['ip'] = ssock.getpeername()[0]
#            ssock.close()

        # Use OpenSSL pip package to get certificate chain instead:
        ctx = ossl.Context(ossl.TLS_CLIENT_METHOD)
        sock = socket.create_connection((host, port))
        conn = ossl.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()
        result['ip'] = str(sock.getpeername()[0])
        chain_der = conn.get_peer_cert_chain(as_cryptography=True)
        conn.close()

        for cert_der in chain_der:
            if isinstance(cert_der, cryptography.x509.Certificate):
                cert = cert_der
            else:
                cert = cryptography.x509.load_der_x509_certificate(cert_der)

            pub_key = cert.public_key()
            algo_name = 'unknown'
            for algo_type in algorithms.keys():
                if isinstance(pub_key, algo_type):
                    algo_name = algorithms[algo_type]

            print(isinstance(pub_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey))
            cert_info = {
                'version': str(cert.version.value),
                'fingerprints': {
                    'sha-256': cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA256()).hex(),
                    'sha-1': cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA1()).hex(),
                },
                'serial_number': cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8).hex(),
                'public_key': {
                    'bits': pub_key.key_size,
                    'key_der': pub_key.public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.DER,
                        cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).hex(),
                    'key_pem': pub_key.public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.PEM,
                        cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    'algorithm': algo_name,
                },
                'not_valid_before_utc': str(cert.not_valid_before_utc),
                'not_valid_after_utc': str(cert.not_valid_after_utc),
                'issuer': {},
                'subject': {},
                'signature': {
                    'algorithm': cert.signature_algorithm_oid._name,
                },
                'raw': {
                    'der': cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER).hex(),
                    'pem': cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM).decode()
                }
            }
            for attrib in cert.issuer:
                cert_info['issuer'][attrib.oid._name] = attrib.value
            for attrib in cert.subject:
                cert_info['subject'][attrib.oid._name] = attrib.value

            result['certificate_chain'].append(cert_info)

    except Exception as e:
        result = { 'error': str(e), 'traceback': traceback.format_exception(e) }

    return Response(
        media_type='application/json',
        status_code=400,
        content=json.dumps(result)
    )