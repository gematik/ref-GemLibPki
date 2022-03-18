# Release 0.6.0

- add certHash extension in OCSP responses (enabled by default)
- add certHash validation of OCSP responses (enabled by default)
- refactor OcspVerifier class to harmonise with CertificateVerifier

# Release 0.5.3

- add C.FD.OSIG certificate profile

# Release 0.5.2

- set AccessLevel from private to protected for class TucPki018Verifier to make it extendable https://github.com/gematik/ref-GemLibPki/pull/2
- raise code coverage

# Release 0.5.1

- P12Container serializable
- P12Reader extended
- dependencies updated

# Release 0.5.0

- API change: Main method for certificate checks "performTucPki18Checks(..)" in
  class [TucPki018Verifier](src/main/java/de/gematik/pki/certificate/TucPki018Verifier.java) returns Admission instead of CertficateType.
- add methods for TSL handling: read, write, modify, sign+validate (RSA/ECC)
- OCSP request implemented, active by default
- additional CertificateProfiles implemented

# Release 0.4.1

- resign test certificates

# Release 0.4.0

- refactoring: separate [TspInformationProvider](src/main/java/de/gematik/pki/tsl/TspInformationProvider.java) from
  [TslInformationProvider](src/main/java/de/gematik/pki/tsl/TslInformationProvider.java)
- OCSP request implemented, not used in certificate checks atm
- cleanup JavaDoc

# Release 0.3.0

- fix https://github.com/gematik/ref-GemLibPki/issues/1
- refactor class names

# Release 0.2.0

- accept several profiles/policies in certificates
- change behavior of certficate checks (for [ext]KeyUsage) to fit gematik certificate profiles
- improve error logging in certificate checks
- fix KeyUsage in cert profile EGK
- rename enum CertificateProfiles to CertificateProfile
- encapsulate eu.europa.esig - lib uk ready now ;-)
- pump code coverage
- refactor packages

# Release 0.1.0

- This is the initial release of GemLibPki
- Certificate checks of TUC_PKI_018 are implemented
- see [README.md](README.md) for usage instructions and further information
