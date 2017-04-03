# Symantec Certificates

This directory contains the set of known active and legacy root certificates
operated by Symantec Corporation. In order for certificates issued from
roots to be trusted, it is required that the certificates be logged using
Certificate Transparency.

For details about why, see <https://security.googleblog.com/2015/10/sustaining-digital-certificate-security.html>

The exception to this is sub-CAs which have been disclosed as independently
operated, whose keys are not in control of Symantec, and which are
maintaining a current and appropriate audit.

## Roots

The full set of roots are in the [roots/](roots/) directory, organized by
SHA-256 hash of the certificate file.

The following command can be used to match certificates and their key hashes:

`` for f in roots/*.pem; do openssl x509 -noout -pubkey -in "${f}" | openssl asn1parse -inform pem -out /tmp/pubkey.out -noout; digest=`cat /tmp/pubkey.out | openssl dgst -sha256 -c | awk -F " " '{print $2}' | sed s/:/,0x/g `; echo "0x${digest} ${f##*/}"; done | sort ``

## Excluded Sub-CAs

### Apple

[WebTrust Audit](https://cert.webtrust.org/ViewSeal?id=1917)
[Certification Practices Statement](http://images.apple.com/certificateauthority/pdf/Apple_IST_CPS_v2.0.pdf)

  * [17f96609ac6ad0a2d6ab0a21b2d1b5b2946bd04dbf120703d1def6fb62f4b661.pem](excluded/17f96609ac6ad0a2d6ab0a21b2d1b5b2946bd04dbf120703d1def6fb62f4b661.pem)
  * [3db76d1dd7d3a759dccc3f8fa7f68675c080cb095e4881063a6b850fdd68b8bc.pem](excluded/3db76d1dd7d3a759dccc3f8fa7f68675c080cb095e4881063a6b850fdd68b8bc.pem)
  * [6115f06a338a649e61585210e76f2ece3989bca65a62b066040cd7c5f408edd0.pem](excluded/6115f06a338a649e61585210e76f2ece3989bca65a62b066040cd7c5f408edd0.pem)
  * [904fb5a437754b1b32b80ebae7416db63d05f56a9939720b7c8e3dcc54f6a3d1.pem](excluded/904fb5a437754b1b32b80ebae7416db63d05f56a9939720b7c8e3dcc54f6a3d1.pem)
  * [ac2b922ecfd5e01711772fea8ed372de9d1e2245fce3f57a9cdbec77296a424b.pem](excluded/ac2b922ecfd5e01711772fea8ed372de9d1e2245fce3f57a9cdbec77296a424b.pem)

### Google

[WebTrust Audit](https://cert.webtrust.org/ViewSeal?id=1941)
[Certification Practices Statement](http://static.googleusercontent.com/media/pki.google.com/en//GIAG2-CPS-1.3.pdf)

  * [c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36.pem](excluded/c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36.pem)

