# About

This project provides a rather simple API endpoint for certificate chain dumping from any reachable
SSL/TLS host.
The necessity of this project stems from current client side JavaScript implementations missing the
functionality to retrieve this information natively.
This API endpoint aims to fill this gap.

# Requirements

* Node.js 20
* Python 3.12

Older or newer versions might work as well, I just didn't try.

# Usage

## Install dependencies:

* `npm install`
* `pip3 install -r requirements.txt`

## Run

Run by typing `npm run dev`. If that results in python not found errors, try running `npm run next-dev` and `npm run python-dev` in two separate shells.

## Queries

You can query the certificate chain for a host using this URL:

    http://localhost:3000/api/py/v1/dumpCerts?host=<hostname>

The result will be a JSON document containing the complete certificate chain if the connection succeeded.
See the [Example](#example) section for exemplary output.

You can also pass a port and an IP address (v4/v6) for the connection, if omitted the port will default to 443 and
the IP will be retrieved through DNS:

    http://localhost:3000/api/py/v1/dumpCerts?host=<hostname>&port=<port>&ip=<ip>

Note that the result certificates `extensions` structure is strongly tied to pythons cryptography library internals
and thus may vary between python versions.
In case you need to rely on any of these it might make sense to change their output to a fixed format.

Note that no requests (besides the initialization of the SSL/TLS connection) will be sent to or accepted from the host.
The connection will be closed directly after the SSL/TLS handshake.

## Encoding

Hostnames using URL-escaped UTF-8 and Punicode encodings are supported, e.g.

    http://localhost:3000/api/py/v1/dumpCerts?host=m%C3%BCnchen.de
    http://localhost:3000/api/py/v1/dumpCerts?host=xn--mnchen-3ya.de

## Ciphers

You can select the accepted ciphers by adding a `ciphers` parameter to the query:

    http://localhost:3000/api/py/v1/dumpCerts?host=github.com&ciphers=aRSA:aECDSA

Use a colon separated cipher list like it is returned from `openssl ciphers` or documented on the [`ciphers` man page](https://linux.die.net/man/1/ciphers).

Note that the use of this parameter currently disables the use of TLS 1.3 (pyOpenSSL is currently missing the required functionality to set the ciphersuite for TLS 1.3, see [here](https://github.com/pyca/pyopenssl/issues/1224)).

## Other

Automatically generated API documentation is provided under `http://localhost:3000/api/py/docs`

Machine readable API documentation is provided under `http://localhost:3000/api/py/openapi.json` in the [OpenAPI](https://github.com/OAI/OpenAPI-Specification) format.

## Validation

Certificate validation is disabled. The returned certificates are NOT VALIDATED.

## CORS

CORS headers are set to accept anything, so that the API is easily usable from other domains without CORS trouble.

## License

Find a copy of the three-clause BSD license in [LICENSE](LICENSE).

## Example

The result is a json document and will look like the follwing for the query `http://localhost:3000/api/py/v1/dumpCerts?host=letsencrypt.org` on [Let's Encrypt](http://letsencrypt.org):
``` json
{
  "api-version": "1",
  "host": "letsencrypt.org",
  "port": 443,
  "ip": "2a05:d014:58f:6201::65",
  "ciphers": "default",
  "cipher-version": "TLSv1.3",
  "certificate-chain": [
    {
      "version": "2",
      "fingerprints": {
        "sha-256": "7d921c5f7354774984ae474f33c75458a7bd3a530013efea8307299ef647fb4a",
        "sha-1": "6c98a3ef277a0d37dbd34d5ed7f417c018b57d5b"
      },
      "serial-number": "04c7a73a361ac02b67bdbd6af210285b1cc7",
      "public-key": {
        "bits": 256,
        "key-der": "3059301306072a8648ce3d020106082a8648ce3d0301070342000438071da21e33063300f3bd6607de19a9ec51e151374b16e0adb79eb569a515df8c7bcdfbcdefb47d7bd21b210ab2006512422fe08f700d8d52a98b89274cfccf",
        "key-pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOAcdoh4zBjMA871mB94ZqexR4VE3\nSxbgrbeetWmlFd+Me837ze+0fXvSGyEKsgBlEkIv4I9wDY1SqYuJJ0z8zw==\n-----END PUBLIC KEY-----\n",
        "algorithm": "Elliptic Curve",
        "details": {
          "curve": {
            "key-size": "256",
            "name": "secp256r1"
          },
          "key-size": "256"
        }
      },
      "not-valid-before-utc": "2024-12-07 14:44:05+00:00",
      "not-valid-after-utc": "2025-03-07 14:44:04+00:00",
      "issuer": {
        "countryName": "US",
        "organizationName": "Let's Encrypt",
        "commonName": "E6"
      },
      "subject": {
        "commonName": "letsencrypt.org"
      },
      "signature-algorithm": {
        "oid-dotted": "1.2.840.10045.4.3.3",
        "oid-name": "ecdsa-with-SHA384"
      },
      "raw": {
        "der": "308203d43082035aa003020102021204c7a73a361ac02b67bdbd6af210285b1cc7300a06082a8648ce3d0403033032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313024536301e170d3234313230373134343430355a170d3235303330373134343430345a301a311830160603550403130f6c657473656e63727970742e6f72673059301306072a8648ce3d020106082a8648ce3d0301070342000438071da21e33063300f3bd6607de19a9ec51e151374b16e0adb79eb569a515df8c7bcdfbcdefb47d7bd21b210ab2006512422fe08f700d8d52a98b89274cfccfa382026630820262300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e041604143d8c2ed727c0158c16e91c5f8c0c7d8090502300301f0603551d230418301680149327469803a951688e98d6c44248db23bf5894d2305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f65362e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f65362e692e6c656e63722e6f72672f306f0603551d110468306682096c656e63722e6f7267820f6c657473656e63727970742e636f6d820f6c657473656e63727970742e6f7267820d7777772e6c656e63722e6f726782137777772e6c657473656e63727970742e636f6d82137777772e6c657473656e63727970742e6f726730130603551d20040c300a3008060667810c01020130820104060a2b06010401d6790204020481f50481f200f00076007d591e12e1782a7b1c61677c5efdf8d0875c14a04e959eb9032fd90e8c2e79b800000193a1c9787d0000040300473045022005e855cd0144ae842cbd10d651eff906eba1b9c188fb6172bd84ee0d08ba590702210095592256417deca791fc0b775dd24d4586c975ad2229a2ada8acb4287ee28198007600134adf1ab5984209780c6fef4c7a91a416b72349ce58576adfaedaa7c2abe02200000193a1c979340000040300473045022100feca19bfea5c0c316cb105a075e4c921837b6c402b6bd03383e2ebc0cdceb71402201e08d776e1826c1ff7553b5108659f9a45924bdcfe0a37ced4eea19331965c1a300a06082a8648ce3d0403030368003065023100a54bcf15b4dca93ca89301b56402c397604873563861bd3aad375ce1abf34f76b31f44cf3dd7b1759eabc26fa24163840230099397fd48f17477e057f3ba82488d011435168903c9f4b40a5ca73e4f69b0c4cf565e505a0609ce356b25a8008ed266",
        "pem": "-----BEGIN CERTIFICATE-----\nMIID1DCCA1qgAwIBAgISBMenOjYawCtnvb1q8hAoWxzHMAoGCCqGSM49BAMDMDIx\nCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\nNjAeFw0yNDEyMDcxNDQ0MDVaFw0yNTAzMDcxNDQ0MDRaMBoxGDAWBgNVBAMTD2xl\ndHNlbmNyeXB0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDgHHaIeMwYz\nAPO9ZgfeGansUeFRN0sW4K23nrVppRXfjHvN+83vtH170hshCrIAZRJCL+CPcA2N\nUqmLiSdM/M+jggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYB\nBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFD2MLtcnwBWM\nFukcX4wMfYCQUCMAMB8GA1UdIwQYMBaAFJMnRpgDqVFojpjWxEJI2yO/WJTSMFUG\nCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL2U2Lm8ubGVuY3Iub3Jn\nMCIGCCsGAQUFBzAChhZodHRwOi8vZTYuaS5sZW5jci5vcmcvMG8GA1UdEQRoMGaC\nCWxlbmNyLm9yZ4IPbGV0c2VuY3J5cHQuY29tgg9sZXRzZW5jcnlwdC5vcmeCDXd3\ndy5sZW5jci5vcmeCE3d3dy5sZXRzZW5jcnlwdC5jb22CE3d3dy5sZXRzZW5jcnlw\ndC5vcmcwEwYDVR0gBAwwCjAIBgZngQwBAgEwggEEBgorBgEEAdZ5AgQCBIH1BIHy\nAPAAdgB9WR4S4XgqexxhZ3xe/fjQh1wUoE6VnrkDL9kOjC55uAAAAZOhyXh9AAAE\nAwBHMEUCIAXoVc0BRK6ELL0Q1lHv+QbrobnBiPthcr2E7g0IulkHAiEAlVkiVkF9\n7KeR/At3XdJNRYbJda0iKaKtqKy0KH7igZgAdgATSt8atZhCCXgMb+9MepGkFrcj\nSc5YV2rfrtqnwqvgIgAAAZOhyXk0AAAEAwBHMEUCIQD+yhm/6lwMMWyxBaB15Mkh\ng3tsQCtr0DOD4uvAzc63FAIgHgjXduGCbB/3VTtRCGWfmkWSS9z+CjfO1O6hkzGW\nXBowCgYIKoZIzj0EAwMDaAAwZQIxAKVLzxW03Kk8qJMBtWQCw5dgSHNWOGG9Oq03\nXOGr8092sx9Ezz3XsXWeq8JvokFjhAIwCZOX/UjxdHfgV/O6gkiNARQ1FokDyfS0\nClynPk9psMTPVl5QWgYJzjVrJagAjtJm\n-----END CERTIFICATE-----\n"
      },
      "extensions": [
        {
          "critical": "True",
          "oid": {
            "oid-dotted": "2.5.29.15",
            "oid-name": "keyUsage"
          },
          "value": {
            "content-commitment": "False",
            "crl-sign": "False",
            "data-encipherment": "False",
            "decipher-only": "False",
            "digital-signature": "True",
            "encipher-only": "False",
            "key-agreement": "False",
            "key-cert-sign": "False",
            "key-encipherment": "False",
            "oid": {
              "oid-dotted": "2.5.29.15",
              "oid-name": "keyUsage"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.37",
            "oid-name": "extendedKeyUsage"
          },
          "value": {
            "usages": [
              {
                "oid-dotted": "1.3.6.1.5.5.7.3.1",
                "oid-name": "serverAuth"
              },
              {
                "oid-dotted": "1.3.6.1.5.5.7.3.2",
                "oid-name": "clientAuth"
              }
            ],
            "oid": {
              "oid-dotted": "2.5.29.37",
              "oid-name": "extendedKeyUsage"
            }
          }
        },
        {
          "critical": "True",
          "oid": {
            "oid-dotted": "2.5.29.19",
            "oid-name": "basicConstraints"
          },
          "value": {
            "ca": "False",
            "path-length": "None",
            "oid": {
              "oid-dotted": "2.5.29.19",
              "oid-name": "basicConstraints"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.14",
            "oid-name": "subjectKeyIdentifier"
          },
          "value": {
            "digest": "3d8c2ed727c0158c16e91c5f8c0c7d8090502300",
            "key-identifier": "3d8c2ed727c0158c16e91c5f8c0c7d8090502300",
            "oid": {
              "oid-dotted": "2.5.29.14",
              "oid-name": "subjectKeyIdentifier"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.35",
            "oid-name": "authorityKeyIdentifier"
          },
          "value": {
            "authority-cert-issuer": "None",
            "authority-cert-serial-number": "None",
            "key-identifier": "9327469803a951688e98d6c44248db23bf5894d2",
            "oid": {
              "oid-dotted": "2.5.29.35",
              "oid-name": "authorityKeyIdentifier"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "1.3.6.1.5.5.7.1.1",
            "oid-name": "authorityInfoAccess"
          },
          "value": {
            "descriptions": [
              {
                "AccessDescription": {
                  "method": {
                    "oid-dotted": "1.3.6.1.5.5.7.48.1",
                    "oid-name": "OCSP"
                  },
                  "location": "http://e6.o.lencr.org"
                }
              },
              {
                "AccessDescription": {
                  "method": {
                    "oid-dotted": "1.3.6.1.5.5.7.48.2",
                    "oid-name": "caIssuers"
                  },
                  "location": "http://e6.i.lencr.org/"
                }
              }
            ],
            "oid": {
              "oid-dotted": "1.3.6.1.5.5.7.1.1",
              "oid-name": "authorityInfoAccess"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.17",
            "oid-name": "subjectAltName"
          },
          "value": {
            "general-names": {
              "general-names": [
                "lencr.org",
                "letsencrypt.com",
                "letsencrypt.org",
                "www.lencr.org",
                "www.letsencrypt.com",
                "www.letsencrypt.org"
              ]
            },
            "oid": {
              "oid-dotted": "2.5.29.17",
              "oid-name": "subjectAltName"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.32",
            "oid-name": "certificatePolicies"
          },
          "value": {
            "policies": [
              {
                "policy-identifier": {
                  "oid-dotted": "2.23.140.1.2.1"
                },
                "policy-qualifiers": "None"
              }
            ],
            "oid": {
              "oid-dotted": "2.5.29.32",
              "oid-name": "certificatePolicies"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "1.3.6.1.4.1.11129.2.4.2",
            "oid-name": "signedCertificateTimestampList"
          },
          "value": {
            "signed-certificate-timestamps": [
              {
                "entry-type": {
                  "name": "PRE_CERTIFICATE",
                  "value": "1"
                },
                "extension-bytes": "",
                "log-id": "7d591e12e1782a7b1c61677c5efdf8d0875c14a04e959eb9032fd90e8c2e79b8",
                "signature": "3045022005e855cd0144ae842cbd10d651eff906eba1b9c188fb6172bd84ee0d08ba590702210095592256417deca791fc0b775dd24d4586c975ad2229a2ada8acb4287ee28198",
                "signature-algorithm": {
                  "name": "ECDSA",
                  "value": "3"
                },
                "signature-hash-algorithm": "sha256",
                "timestamp": "2024-12-07 15:42:35.645000",
                "version": {
                  "name": "v1",
                  "value": "0"
                }
              },
              {
                "entry-type": {
                  "name": "PRE_CERTIFICATE",
                  "value": "1"
                },
                "extension-bytes": "",
                "log-id": "134adf1ab5984209780c6fef4c7a91a416b72349ce58576adfaedaa7c2abe022",
                "signature": "3045022100feca19bfea5c0c316cb105a075e4c921837b6c402b6bd03383e2ebc0cdceb71402201e08d776e1826c1ff7553b5108659f9a45924bdcfe0a37ced4eea19331965c1a",
                "signature-algorithm": {
                  "name": "ECDSA",
                  "value": "3"
                },
                "signature-hash-algorithm": "sha256",
                "timestamp": "2024-12-07 15:42:35.828000",
                "version": {
                  "name": "v1",
                  "value": "0"
                }
              }
            ],
            "oid": {
              "oid-dotted": "1.3.6.1.4.1.11129.2.4.2",
              "oid-name": "signedCertificateTimestampList"
            }
          }
        }
      ]
    },
    {
      "version": "2",
      "fingerprints": {
        "sha-256": "76e9e288aafc0e37f4390cbf946aad997d5c1c901b3ce513d3d8fadbabe2ab85",
        "sha-1": "c94dc4831a901a9fec0fb49b71bd49b5aad4fad0"
      },
      "serial-number": "b0573e9173972770dbb487cb3a452b38",
      "public-key": {
        "bits": 384,
        "key-der": "3076301006072a8648ce3d020106052b8104002203620004d9f19e4687f8217160a826eba3fab9eada1db912a7d426d95114b1617c7596bf220b391fd5bed10a46aa2d3c4a09842ebe409555e91940376675ed324e770449f8707bc318e7cef77110feac74d800d4ed6d1c731633109c3ab2ea6c62f4bdb8",
        "key-pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2fGeRof4IXFgqCbro/q56toduRKn1CbZ\nURSxYXx1lr8iCzkf1b7RCkaqLTxKCYQuvkCVVekZQDdmde0yTncESfhwe8MY5873\ncRD+rHTYANTtbRxzFjMQnDqy6mxi9L24\n-----END PUBLIC KEY-----\n",
        "algorithm": "Elliptic Curve",
        "details": {
          "curve": {
            "key-size": "384",
            "name": "secp384r1"
          },
          "key-size": "384"
        }
      },
      "not-valid-before-utc": "2024-03-13 00:00:00+00:00",
      "not-valid-after-utc": "2027-03-12 23:59:59+00:00",
      "issuer": {
        "countryName": "US",
        "organizationName": "Internet Security Research Group",
        "commonName": "ISRG Root X1"
      },
      "subject": {
        "countryName": "US",
        "organizationName": "Let's Encrypt",
        "commonName": "E6"
      },
      "signature-algorithm": {
        "oid-dotted": "1.2.840.113549.1.1.11",
        "oid-name": "sha256WithRSAEncryption"
      },
      "raw": {
        "der": "308204573082023fa003020102021100b0573e9173972770dbb487cb3a452b38300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3234303331333030303030305a170d3237303331323233353935395a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b30090603550403130245363076301006072a8648ce3d020106052b8104002203620004d9f19e4687f8217160a826eba3fab9eada1db912a7d426d95114b1617c7596bf220b391fd5bed10a46aa2d3c4a09842ebe409555e91940376675ed324e770449f8707bc318e7cef77110feac74d800d4ed6d1c731633109c3ab2ea6c62f4bdb8a381f83081f5300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030206082b0601050507030130120603551d130101ff040830060101ff020100301d0603551d0e041604149327469803a951688e98d6c44248db23bf5894d2301f0603551d2304183016801479b459e67bb6e5e40173800888c81a58f6e99b6e303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f78312e692e6c656e63722e6f72672f30130603551d20040c300a3008060667810c01020130270603551d1f0420301e301ca01aa0188616687474703a2f2f78312e632e6c656e63722e6f72672f300d06092a864886f70d01010b050003820201007d8b7b4a2035b20586088a6e9e4e3aaf8004c4845c33190a81484d96baefd41db584e69737fe66884f8b3936eb72653f33dcaf0ba31563bdf418d1682fc22127c8fcbeb38ba4c636d8e3fa6da4b593d60caed0d3970247a066f2d384e14d47810e4b12f518ae1ef89c66a05e75074817ae6966e86978370605c2e261ab10aff10ee60c71b4bc939a0b0748e55205c14e9fd960bfb2c408fabd8bb99f1f79a9c60ad1292c47a4ea19d0a5cc701fa11eebe59251e7b6f708d2630c4349a1623eaab4c152b64175469086dc83dd230a55090aaef0657bb3cb9b927473b3edc2fc19b5f5114ea223e90e4c2fc8d7ef990d785e4caaa8a2b9a19f33843df69054509316bcb994ae878693226171927bb7f70681c484571388cac6502641ce108c5668ab52a642a420d09ff5245f11945bc96acd557232ef625bd4076b7a9e93baa108c1de5f8f35fd03a501fb894c775b3e408d00a2e8bdb9163c84d3aaba059fd0966b58765ffc6586a8e1246a3c4b3fe9c02217e41fe73836524696b43a619752ca32e4cd2e8b6fb17f7d1cfebd5767da3727a0a1d4342f24c0a6bfef4f4d583c4e3abcdb032e02bee1c2fa4ebcc2fdae1672617949127ddfccebbff76e2472d740892ee6fd3e1303b2e7d1dd9b43d3fc4afff387435740928dd47fd97b99337929cac48a2e00f570a88303e21182e3830b17cef5cc98220e3abfd985981bf21f4e",
        "pem": "-----BEGIN CERTIFICATE-----\nMIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw\nWhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5G\nh/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV\n6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgw\ngfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD\nATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsj\nv1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB\nAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g\nBAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu\nY3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRc\nMxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOL\npMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhp\neDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxH\npOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7\ns8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSu\nh4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLv\nYlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8\nZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0\nLyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+\nEwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyY\nIg46v9mFmBvyH04=\n-----END CERTIFICATE-----\n"
      },
      "extensions": [
        {
          "critical": "True",
          "oid": {
            "oid-dotted": "2.5.29.15",
            "oid-name": "keyUsage"
          },
          "value": {
            "content-commitment": "False",
            "crl-sign": "True",
            "data-encipherment": "False",
            "decipher-only": "False",
            "digital-signature": "True",
            "encipher-only": "False",
            "key-agreement": "False",
            "key-cert-sign": "True",
            "key-encipherment": "False",
            "oid": {
              "oid-dotted": "2.5.29.15",
              "oid-name": "keyUsage"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.37",
            "oid-name": "extendedKeyUsage"
          },
          "value": {
            "usages": [
              {
                "oid-dotted": "1.3.6.1.5.5.7.3.2",
                "oid-name": "clientAuth"
              },
              {
                "oid-dotted": "1.3.6.1.5.5.7.3.1",
                "oid-name": "serverAuth"
              }
            ],
            "oid": {
              "oid-dotted": "2.5.29.37",
              "oid-name": "extendedKeyUsage"
            }
          }
        },
        {
          "critical": "True",
          "oid": {
            "oid-dotted": "2.5.29.19",
            "oid-name": "basicConstraints"
          },
          "value": {
            "ca": "True",
            "path-length": "0",
            "oid": {
              "oid-dotted": "2.5.29.19",
              "oid-name": "basicConstraints"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.14",
            "oid-name": "subjectKeyIdentifier"
          },
          "value": {
            "digest": "9327469803a951688e98d6c44248db23bf5894d2",
            "key-identifier": "9327469803a951688e98d6c44248db23bf5894d2",
            "oid": {
              "oid-dotted": "2.5.29.14",
              "oid-name": "subjectKeyIdentifier"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.35",
            "oid-name": "authorityKeyIdentifier"
          },
          "value": {
            "authority-cert-issuer": "None",
            "authority-cert-serial-number": "None",
            "key-identifier": "79b459e67bb6e5e40173800888c81a58f6e99b6e",
            "oid": {
              "oid-dotted": "2.5.29.35",
              "oid-name": "authorityKeyIdentifier"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "1.3.6.1.5.5.7.1.1",
            "oid-name": "authorityInfoAccess"
          },
          "value": {
            "descriptions": [
              {
                "AccessDescription": {
                  "method": {
                    "oid-dotted": "1.3.6.1.5.5.7.48.2",
                    "oid-name": "caIssuers"
                  },
                  "location": "http://x1.i.lencr.org/"
                }
              }
            ],
            "oid": {
              "oid-dotted": "1.3.6.1.5.5.7.1.1",
              "oid-name": "authorityInfoAccess"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.32",
            "oid-name": "certificatePolicies"
          },
          "value": {
            "policies": [
              {
                "policy-identifier": {
                  "oid-dotted": "2.23.140.1.2.1"
                },
                "policy-qualifiers": "None"
              }
            ],
            "oid": {
              "oid-dotted": "2.5.29.32",
              "oid-name": "certificatePolicies"
            }
          }
        },
        {
          "critical": "False",
          "oid": {
            "oid-dotted": "2.5.29.31",
            "oid-name": "cRLDistributionPoints"
          },
          "value": {
            "distribution-points": [
              {
                "crl-issuer": "None",
                "full-name": [
                  "http://x1.c.lencr.org/"
                ],
                "reasons": "None",
                "relative-name": "None"
              }
            ],
            "oid": {
              "oid-dotted": "2.5.29.31",
              "oid-name": "cRLDistributionPoints"
            }
          }
        }
      ]
    }
  ]
}
```
