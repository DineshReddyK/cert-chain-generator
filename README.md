# Certificate chain generator

This tool can be used generate certificate chain, optionally, revoke them and generate crls.
This will be done based on the input configuration file.


### Help

```
python prepate_certchain.py <input_file>


Input File Format:

Cert chain      | Revoked Certs
rca1->ica1->ee1 | ee1
rca2->ica2->ee2 | ica2,ee2
```
