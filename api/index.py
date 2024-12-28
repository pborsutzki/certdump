import cryptography.hazmat
import cryptography.hazmat.bindings
import cryptography.hazmat.bindings.openssl
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.asymmetric
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.types
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.bindings._rust
import cryptography.x509
import cryptography.x509.extensions
import cryptography.x509.oid
from datetime import datetime
from fastapi import FastAPI, Response

import socket
import ssl
import cryptography
import json
from typing import cast

import traceback
import inspect
from pprint import pprint

from OpenSSL import SSL as ossl

from fastapi.middleware.cors import CORSMiddleware

### Create FastAPI instance with custom docs and openapi url
app = FastAPI(
    docs_url="/api/py/docs",
    openapi_url="/api/py/openapi.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'])

def format_names(n: str):
    # trim leading and trailing underscores
    if len(n) > 0 and n[0] == '_':
        n = n[1:]
    if len(n) > 0 and n[-1] == '_':
        n = n[:-1]
    return n.replace('_', '-')

def stringify(e, depth=0):
    if depth > 10:
        return 'depth exceeded'
    depth += 1
    if isinstance(e, cryptography.x509.extensions.Extension):
        return stringify(e.value, depth)
    if isinstance(e, cryptography.x509.ObjectIdentifier):
        oid = cast(cryptography.x509.ObjectIdentifier, e)
        result = {
            'oid-dotted': oid.dotted_string
        }
        if oid._name != 'Unknown OID':
            result['oid-name'] = oid._name

        return result
    if isinstance(e, cryptography.x509.AccessDescription):
        ad = cast(cryptography.x509.AccessDescription, e)
        return { 'AccessDescription': {
            'method': stringify(ad.access_method, depth),
            'location': stringify(ad.access_location, depth),
            } }
    if isinstance(e, cryptography.x509.GeneralNames):
        return [stringify(x, depth) for x in e._general_names]
    if isinstance(e, cryptography.x509.GeneralName):
        return e.value
    if isinstance(e, cryptography.x509.SignedCertificateTimestamps):
        return e.public_bytes().hex()
    if isinstance(e, cryptography.hazmat.primitives.hashes.HashAlgorithm):
        return e.name
    if isinstance(e, str):
        return e
    if isinstance(e, list):
        return [stringify(x, depth) for x in e]
    if isinstance(e, bytes):
        return e.hex()
    if isinstance(e, datetime):
        return str(e)
    if isinstance(e, int):
        return str(e)
    if isinstance(e, bool):
        return str(e)

    if dir(e):
        result = {}

        if hasattr(e, 'public_bytes'):
            result['public-bytes'] = e.public_bytes().hex()

        for attr in dir(e):
            if not '__' in str(attr) and not str(attr) == '_abc_impl':
                try:
                    val = getattr(e, attr)
                    if not inspect.ismethod(val):
                        result[format_names(str(attr))] = stringify(val, depth)
                except Exception:
                    pass

        if result:
            #result['type'] = str(type(e))
            return result

    return str(e)

@app.get("/api/py/v1/dumpCerts")
def dump_certs(host: str, port: int = 443, ciphers: str = None, ip: str = None):
    result = {
        'api-version': '1',
        'host': host,
        'port': port,
        'ip': ip,
        'ciphers': ciphers if ciphers else 'default',
        'cipher-version': 'unknown',
        'certificate-chain': []
    }
    status = 200
    try:
        cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes
        algorithms = {
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey: 'Elliptic Curve',
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: 'RSA'
        }

        chain_der = []
        if False:
            # get_unverified_chain call using pythons default crypto lib requires python 3.13,
            # Vercel only supports 3.12 at the time of writing ...
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(socket.create_connection((ip if ip else host, port)), server_hostname=host) as ssock:
                chain_der += ssock.get_unverified_chain()
                result['ip'] = ssock.getpeername()[0]
                result['cipher-version'] = ssock.version()
                ssock.close()
        else:
            # ... so use the OpenSSL pip package to get certificate chain instead:
            ctx = ossl.Context(ossl.TLS_CLIENT_METHOD)

            if ciphers:
                ctx.set_cipher_list(ciphers.encode('ascii'))
                # set_cipher_list does not work with tls1.3, like openssl -cipher doesn't work.
                # You should use -ciphersuites instead but this API currently doesn't support it, so
                # we instead disable tls 1.3.
                ctx.set_options(ossl.OP_NO_TLSv1_3)

            ctx.set_verify(ossl.VERIFY_NONE) # interestingly, this is the default with pyOpenSSL ... oO

            sock = socket.create_connection((ip if ip else host, port))
            conn = ossl.Connection(ctx, sock)
            conn.set_tlsext_host_name(host.encode())
            conn.set_connect_state()
            conn.do_handshake()
            result['ip'] = str(sock.getpeername()[0])
            chain_der = conn.get_peer_cert_chain(as_cryptography=True)
            result['cipher-version'] = conn.get_cipher_version()
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

            cert_info = {
                'version': str(cert.version.value),
                'fingerprints': {
                    'sha-256': cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA256()).hex(),
                    'sha-1': cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA1()).hex(),
                },
                'serial-number': cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8).hex(),
                'public-key': {
                    'bits': pub_key.key_size,
                    'key-der': pub_key.public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.DER,
                        cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).hex(),
                    'key-pem': pub_key.public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.PEM,
                        cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    'algorithm': algo_name,
                },
                'not-valid-before-utc': str(cert.not_valid_before_utc),
                'not-valid-after-utc': str(cert.not_valid_after_utc),
                'issuer': {},
                'subject': {},
                'signature-algorithm': stringify(cert.signature_algorithm_oid),
                'raw': {
                    'der': cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER).hex(),
                    'pem': cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM).decode()
                }
            }
            for attrib in cert.issuer:
                cert_info['issuer'][attrib.oid._name] = attrib.value
            for attrib in cert.subject:
                cert_info['subject'][attrib.oid._name] = attrib.value

            cert_info['extensions'] = stringify(cert.extensions._extensions)

            result['certificate-chain'].append(cert_info)

    except Exception as e:
        result = { 'error': str(e), 'traceback': traceback.format_exception(e) }
        status = 400

    return Response(
        media_type='application/json',
        status_code=status,
        content=json.dumps(result)
    )