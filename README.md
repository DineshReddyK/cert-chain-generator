# certificate chain generator

Generates the certificate chain and optionally revokes any certificates.


### help

```
python prepate_certchain.py <input_file>


Input File Format:

Cert chain      | Revoked Certs
rca1->ica1->ee1 | ee1
rca2->ica2->ee2 | ica2,ee2
```
