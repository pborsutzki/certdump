## Introduction

This project provides a simple certificate chain dump API endpoint for any given host on a port.

## Usage

Query the certificate chain using this URL:
`http://localhost:3000/api/py/v1/dumpCerts?host=letsencrypt.org`

You can also pass a port for the connection, if omitted it will default to 443:
`http://localhost:3000/api/py/v1/dumpCerts?host=letsencrypt.org&port=443`
