# Certificate Blacklist

This directory contains a number of certificates and public keys which are
considered blacklisted within Chromium-based products. 

When applicable, additional information and the full certificate or key
are included.

## Compromises & Misissuances

### Comodo

For details, see <https://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html>,
<https://blog.mozilla.org/security/2011/03/25/comodo-certificate-issue-follow-up/>,
and <https://technet.microsoft.com/en-us/library/security/2524375.aspx>.

As the result of a compromise of a partner RA of Comodo, nine certificates were
misissued, for a variety of online services.

  * [2a3699deca1e9fd099ba45de8489e205977c9f2a5e29d5dd747381eec0744d71.pem](2a3699deca1e9fd099ba45de8489e205977c9f2a5e29d5dd747381eec0744d71.pem)
  * [4bf6bb839b03b72839329b4ea70bb1b2f0d07e014d9d24aa9cc596114702bee3.pem](4bf6bb839b03b72839329b4ea70bb1b2f0d07e014d9d24aa9cc596114702bee3.pem)
  * [79f69a47cfd6c4b4ceae8030d04b49f6171d3b5d6c812f58d040e586f1cb3f14.pem](79f69a47cfd6c4b4ceae8030d04b49f6171d3b5d6c812f58d040e586f1cb3f14.pem)
  * [8290cc3fc1c3aac3239782c141ace8f88aeef4e9576a43d01867cf19d025be66.pem](8290cc3fc1c3aac3239782c141ace8f88aeef4e9576a43d01867cf19d025be66.pem)
  * [933f7d8cda9f0d7c8bfd3c22bf4653f4161fd38ccdcf66b22e95a2f49c2650f8.pem](933f7d8cda9f0d7c8bfd3c22bf4653f4161fd38ccdcf66b22e95a2f49c2650f8.pem)
  * [9532e8b504964331c271f3f5f10070131a08bf8ba438978ce394c34feeae246f.pem](9532e8b504964331c271f3f5f10070131a08bf8ba438978ce394c34feeae246f.pem)
  * [be144b56fb1163c49c9a0e6b5a458df6b29f7e6449985960c178a4744624b7bc.pem](be144b56fb1163c49c9a0e6b5a458df6b29f7e6449985960c178a4744624b7bc.pem)
  * [ead610e6e90b439f2ecb51628b0932620f6ef340bd843fca38d3181b8f4ba197.pem](ead610e6e90b439f2ecb51628b0932620f6ef340bd843fca38d3181b8f4ba197.pem)
  * [f8a5ff189fedbfe34e21103389a68340174439ad12974a4e8d4d784d1f3a0faa.pem](f8a5ff189fedbfe34e21103389a68340174439ad12974a4e8d4d784d1f3a0faa.pem)

### DigiNotar

For details, see <https://googleonlinesecurity.blogspot.com/2011/08/update-on-attempted-man-in-middle.html>
and <https://en.wikipedia.org/wiki/DigiNotar>.

As a result of a complete CA compromise, the following certificates (and
their associated public keypairs) are revoked.

  * [0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217.pem](0d136e439f0ab6e97f3a02a540da9f0641aa554e1d66ea51ae2920d51b2f7217.pem)
  * [294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61.pem](294f55ef3bd7244c6ff8a68ab797e9186ec27582751a791515e3292e48372d61.pem)
  * [31c8fd37db9b56e708b03d1f01848b068c6da66f36fb5d82c008c6040fa3e133.pem](31c8fd37db9b56e708b03d1f01848b068c6da66f36fb5d82c008c6040fa3e133.pem)
  * [3946901f46b0071e90d78279e82fababca177231a704be72c5b0e8918566ea66.pem](3946901f46b0071e90d78279e82fababca177231a704be72c5b0e8918566ea66.pem)
  * [450f1b421bb05c8609854884559c323319619e8b06b001ea2dcbb74a23aa3be2.pem](450f1b421bb05c8609854884559c323319619e8b06b001ea2dcbb74a23aa3be2.pem)
  * [4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176.pem](4fee0163686ecbd65db968e7494f55d84b25486d438e9de558d629d28cd4d176.pem)
  * [8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af.pem](8a1bd21661c60015065212cc98b1abb50dfd14c872a208e66bae890f25c448af.pem)
  * [9ed8f9b0e8e42a1656b8e1dd18f42ba42dc06fe52686173ba2fc70e756f207dc.pem](9ed8f9b0e8e42a1656b8e1dd18f42ba42dc06fe52686173ba2fc70e756f207dc.pem)
  * [a686fee577c88ab664d0787ecdfff035f4806f3de418dc9e4d516324fff02083.pem](a686fee577c88ab664d0787ecdfff035f4806f3de418dc9e4d516324fff02083.pem)
  * [b8686723e415534bc0dbd16326f9486f85b0b0799bf6639334e61daae67f36cd.pem](b8686723e415534bc0dbd16326f9486f85b0b0799bf6639334e61daae67f36cd.pem)
  * [fdedb5bdfcb67411513a61aee5cb5b5d7c52af06028efc996cc1b05b1d6cea2b.pem](fdedb5bdfcb67411513a61aee5cb5b5d7c52af06028efc996cc1b05b1d6cea2b.pem)

### India CCA

For details, see <https://googleonlinesecurity.blogspot.com/2014/07/maintaining-digital-certificate-security.html>
and <https://technet.microsoft.com/en-us/library/security/2982792.aspx>

An unknown number of misissued certificates were issued by a sub-CA of
India CCA, the India NIC. Due to the scope of the misissuance, the sub-CA
was wholly revoked, and India CCA was constrained to a subset of India's
ccTLD namespace.

  * [67ed4b703d15dc555f8c444b3a05a32579cb7599bd19c9babe10c584ea327ae0.pem](67ed4b703d15dc555f8c444b3a05a32579cb7599bd19c9babe10c584ea327ae0.pem)
  * [a8e1dfd9cd8e470aa2f443914f931cfd61c323e94d75827affee985241c35ce5.pem](a8e1dfd9cd8e470aa2f443914f931cfd61c323e94d75827affee985241c35ce5.pem)
  * [e4f9a3235df7330255f36412bc849fb630f8519961ec3538301deb896c953da5.pem](e4f9a3235df7330255f36412bc849fb630f8519961ec3538301deb896c953da5.pem)

### Trustwave

For details, see <https://www.trustwave.com/Resources/SpiderLabs-Blog/Clarifying-The-Trustwave-CA-Policy-Update/>
and <https://bugzilla.mozilla.org/show_bug.cgi?id=724929>

Two certificates were issued by Trustwave for use in enterprise
Man-in-the-Middle. The following public key was used for both certificates,
and is revoked.

  * [32ecc96f912f96d889e73088cd031c7ded2c651c805016157a23b6f32f798a3b.key](32ecc96f912f96d889e73088cd031c7ded2c651c805016157a23b6f32f798a3b.key)

### TurkTrust

For details, see <https://googleonlinesecurity.blogspot.com/2013/01/enhancing-digital-certificate-security.html>
and <https://web.archive.org/web/20130326152502/http://turktrust.com.tr/kamuoyu-aciklamasi.2.html>

As a result of a software configuration issue, two certificates were misissued
by Turktrust that failed to properly set the basicConstraints extension.
Because these certificates can be used to issue additional certificates, they
have been revoked.

  * [372447c43185c38edd2ce0e9c853f9ac1576ddd1704c2f54d96076c089cb4227.pem](372447c43185c38edd2ce0e9c853f9ac1576ddd1704c2f54d96076c089cb4227.pem)
  * [42187727be39faf667aeb92bf0cc4e268f6e2ead2cefbec575bdc90430024f69.pem](42187727be39faf667aeb92bf0cc4e268f6e2ead2cefbec575bdc90430024f69.pem)

## Private Key Leakages

### Cyberoam

For details, see <https://blog.torproject.org/blog/security-vulnerability-found-cyberoam-dpi-devices-cve-2012-3372>

Device manufacturer Cyberoam used the same private key for all devices by
default, which subsequently leaked and is included below. The associated
public key is blacklisted.

  * [1af56c98ff043ef92bebff54cebb4dd67a25ba956c817f3e6dd3c1e52eb584c1.key](1af56c98ff043ef92bebff54cebb4dd67a25ba956c817f3e6dd3c1e52eb584c1.key)

### Dell

For details, see <http://www.dell.com/support/article/us/en/19/SLN300321>
and <http://en.community.dell.com/dell-blogs/direct2dell/b/direct2dell/archive/2015/11/23/response-to-concerns-regarding-edellroot-certificate>

The private keys for both the eDellRoot and DSDTestProvider certificates were
trivially extracted, and thus their associated public keys are
blacklisted.

  * [0f912fd7be760be25afbc56bdc09cd9e5dcc9c6f6a55a778aefcb6aa30e31554.pem](0f912fd7be760be25afbc56bdc09cd9e5dcc9c6f6a55a778aefcb6aa30e31554.pem)
  * [ec30c9c3065a06bb07dc5b1c6b497f370c1ca65c0f30c08e042ba6bcecc78f2c.pem](ec30c9c3065a06bb07dc5b1c6b497f370c1ca65c0f30c08e042ba6bcecc78f2c.pem)

### sslip.io

For details, see <https://blog.pivotal.io/labs/labs/sslip-io-a-valid-ssl-certificate-for-every-ip-address>

A subscriber of Comodo's acquired a wildcard certificate for sslip.io, and
then subsequently published the private key, as a means for developers
to avoid having to acquire certificates.

As the private key could be used to intercept all communications to this
domain, the associated public key was blacklisted.

  * [f3bae5e9c0adbfbfb6dbf7e04e74be6ead3ca98a5604ffe591cea86c241848ec.pem](f3bae5e9c0adbfbfb6dbf7e04e74be6ead3ca98a5604ffe591cea86c241848ec.pem)

### xs4all.nl

For details, see <https://raymii.org/s/blog/How_I_got_a_valid_SSL_certificate_for_my_ISPs_main_website.html>

A user of xs4all was able to register a reserved email address that can be
used to cause certificate issuance, as described in the CA/Browser Forum's
Baseline Requirements, and then subsequently published the private key.

  * [83618f932d6947744d5ecca299d4b2820c01483947bd16be814e683f7436be24.pem](83618f932d6947744d5ecca299d4b2820c01483947bd16be814e683f7436be24.pem)

## Miscellaneous

### DigiCert

For details, see <https://bugzilla.mozilla.org/show_bug.cgi?id=1242758> and
<https://bugzilla.mozilla.org/show_bug.cgi?id=1224104>

These two intermediates were retired by DigiCert, and blacklisted for
robustness at their request.

  * [159ca03a88897c8f13817a212629df84ce824709492b8c9adb8e5437d2fc72be.pem](159ca03a88897c8f13817a212629df84ce824709492b8c9adb8e5437d2fc72be.pem)
  * [b8c1b957c077ea76e00b0f45bff5ae3acb696f221d2e062164fe37125e5a8d25.pem](b8c1b957c077ea76e00b0f45bff5ae3acb696f221d2e062164fe37125e5a8d25.pem)

### Hacking Team

The following keys were reported as used by Hacking Team to compromise users,
and are blacklisted for robustness.

  * [c4387d45364a313fbfe79812b35b815d42852ab03b06f11589638021c8f2cb44.key](c4387d45364a313fbfe79812b35b815d42852ab03b06f11589638021c8f2cb44.key)
  * [ea08c8d45d52ca593de524f0513ca6418da9859f7b08ef13ff9dd7bf612d6a37.key](ea08c8d45d52ca593de524f0513ca6418da9859f7b08ef13ff9dd7bf612d6a37.key)

### live.fi

For details, see <https://technet.microsoft.com/en-us/library/security/3046310.aspx>

A user of live.fi was able to register a reserved email address that can be
used to cause certificate issuance, as described in the CA/Browser Forum's
Baseline Requirements. This was not intended by Microsoft, the operators of
live.fi, but conformed to the Baseline Requirements. It was blacklisted for
robustness.

  * [c67d722c1495be02cbf9ef1159f5ca4aa782dc832dc6aa60c9aa076a0ad1e69d.pem](c67d722c1495be02cbf9ef1159f5ca4aa782dc832dc6aa60c9aa076a0ad1e69d.pem)

### SECOM

For details, see <https://bugzilla.mozilla.org/show_bug.cgi?id=1188582>

This intermediate certificate was retired by SECOM, and blacklisted for
robustness at their request.

  * [817d4e05063d5942869c47d8504dc56a5208f7569c3d6d67f3457cfe921b3e29.pem](817d4e05063d5942869c47d8504dc56a5208f7569c3d6d67f3457cfe921b3e29.pem)

### Symantec

For details, see <https://bugzilla.mozilla.org/show_bug.cgi?id=966060> 

These three intermediate certificates were retired by Symantec, and
blacklisted for robustness at their request.

  * [1f17f2cbb109f01c885c94d9e74a48625ae9659665d6d7e7bc5a10332976370f.pem](1f17f2cbb109f01c885c94d9e74a48625ae9659665d6d7e7bc5a10332976370f.pem)
  * [3e26492e20b52de79e15766e6cb4251a1d566b0dbfb225aa7d08dda1dcebbf0a.pem](3e26492e20b52de79e15766e6cb4251a1d566b0dbfb225aa7d08dda1dcebbf0a.pem)
  * [7abd72a323c9d179c722564f4e27a51dd4afd24006b38a40ce918b94960bcf18.pem](7abd72a323c9d179c722564f4e27a51dd4afd24006b38a40ce918b94960bcf18.pem)

### T-Systems

For details, see <https://bugzilla.mozilla.org/show_bug.cgi?id=1076940>

This intermediate certificate was retired by T-Systems, and blacklisted
for robustness at their request.

  * [f4a5984324de98bd979ef181a100cf940f2166173319a86a0d9d7c8fac3b0a8f.pem](f4a5984324de98bd979ef181a100cf940f2166173319a86a0d9d7c8fac3b0a8f.pem)
