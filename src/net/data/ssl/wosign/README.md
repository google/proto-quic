# WoSign Certificates

This directory contains the set of known active and legacy root certificates
operated by WoSign CA Limited, including those of its wholly owned subisiary
StartCom.

Trust in these root certificates is being phased out, as described at
<https://security.googleblog.com/2016/10/distrusting-wosign-and-startcom.html>

## Roots

The files in this directory are organized by the SHA-256 hash of the
certificate file, while the policies are based on the SHA-256 hash of
the subjectPublicKeyInfo contained within the certificate.

The following command can be used to extract the key hashes:

`` for f in *.pem; do openssl x509 -noout -pubkey -in "${f}" | openssl asn1parse -inform pem -out /tmp/pubkey.out -noout; digest=`cat /tmp/pubkey.out | openssl dgst -sha256 -c | sed s/:/,0x/g `; echo "0x${digest} ${f##*/}"; done | sort ``

