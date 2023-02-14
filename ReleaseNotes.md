<img align="right" width="250" height="47" src="doc/images/Gematik_Logo_Flag_With_Background.png"/> <br/>

# Release notes GemLibPki

## Release 0.11.0

- API change: modify [TslSigner](src/main/java/de/gematik/pki/gemlibpki/tsl/TslSigner.java) to be a
  builder
- API change: [TslConverter](src/main/java/de/gematik/pki/gemlibpki/tsl/TslConverter.java) does not
  return optionals anymore
- extend with TslConverter formatting options (pretty print, etc.)
- API change: [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java)
  returns a TslTrustanchorUpdate object to easily verify trust anchor updates
- extend to TucPki001Verifier check TSL id, sequence number and announced trust anchor if applicable
- add possibility to sign TSLs with certificates with incorrect key usages and validities
- extend [TslModifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TslModifier.java) with various
  modification methods
- update dependencies

## Release 0.10.0

- API change
  in [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java)
- add TUC_PKI_012 XML-Signatur-Prüfung to TucPki001Verifier
- extend CertificateID manipulations in OcspResponseGenerator

## Release 0.9.4

- change maven groupId to "de.gematik.pki"
- change OCSP caching behavior
- add certificate profile for ak.aut certs
- updated dependencies
- cleanup and small fixes

## Release 0.9.3

- replace expired test certificates in unit tests for tsl signature and validation
- add unit tests for bouncy castle usage und ocsp edge case
- update dependencies
- repair images

## Release 0.9.2

- BUGFIX: save only ocsp responses to cache with status SUCCESSFUL (0)
- prepare reproducible builds: change line endings to LF

## Release 0.9.1

- fix sonar issue in builder parameter

## Release 0.9.0

- API change: rename enum elements
  in [CertificateProfile](src/main/java/de/gematik/pki/gemlibpki/certificate/CertificateProfile.java)
- API change: rename getTspServiceSubset() to getIssuerTspServiceSubset()
  in [CertificateProfile](src/main/java/de/gematik/pki/gemlibpki/tsl/TspInformationProvider.java)
- Update XAdES4j because of https://github.com/luisgoncalves/xades4j/issues/261. This brings new
  dependencies in jaxb context (glassfish, jakarta, etc.)
- add OCSP validations according to TUC_PKI_006 of gemSpec_PKI
    - timings like producedAt, etc.
    - signature
    - certificate status like revoked and unknown
    - OCSP response status like TryLater, Unauthorized, etc.
    - chertHash
    - certId
    - OCSP timeout
- add possibility to generate OCSP responses with invalid parameter (signature, certId, etc.)
- add ocsp checks against TUC_PKI_018 for TSL signer certificate during TSL validation (TUC_PKI_001)
- add possibility to generate certId with or without null parameter in hash algorithm
- finalize OCSP caching
- add possibility to verify an offline ocsp response
- bug fixes and code improvements

## Release 0.8.1

- change language specific code (>Java 11)
- fix small issues

## Release 0.8.0

- API change: move whole package from de.gematik.pki to de.gematik.pki.gemlibpki
- usage of BouncyCastle as crypto provider enforced in every class/method that deals with brainpool
  curves
- switch code formatting to google java formatter
- switch from OpenJDK 11 to OpenJDK 17
- update dependencies
- update maven plugins
- multiple small bug fixes and improvements

## Release 0.7.1

- API change: rename TucPki001Verifier builder member tspServiceList to currentTrustedServices for
  clarity

## Release 0.7.0

- API change: rename method doOcsp() to doOcspIfConfigured()
  in [TucPki018Verifier](src/main/java/de/gematik/pki/certificate/TucPki018Verifier.java)
- API change: rework exception handling
- add class [TucPki001Verifier](src/main/java/de/gematik/pki/tsl/TucPki001Verifier.java) for checks
  of TSL.
  The only check at the moment is the ocsp status of the TSL signing certificate.

## Release 0.6.2

- allow disabling of OCSP checks
- add dependency checks for CVE's
- refactor unit tests
- update dependencies

## Release 0.6.1

- BUGFIX: make certHash extension non-critical
- BUGFIX: correct certHash extension to be part of single response instead of basic response

## Release 0.6.0

- add certHash extension in OCSP responses (enabled by default)
- add certHash validation of OCSP responses (enabled by default)
- refactor OcspVerifier class to harmonise with CertificateVerifier

## Release 0.5.3

- add C.FD.OSIG certificate profile

## Release 0.5.2

- set AccessLevel from private to protected for class TucPki018Verifier to make it
  extendable https://github.com/gematik/ref-GemLibPki/pull/2
- raise code coverage

## Release 0.5.1

- P12Container serializable
- P12Reader extended
- dependencies updated

## Release 0.5.0

- API change: Main method for certificate checks "performTucPki18Checks(..)" in
  class [TucPki018Verifier](src/main/java/de/gematik/pki/certificate/TucPki018Verifier.java) returns
  Admission instead
  of CertficateType.
- add methods for TSL handling: read, write, modify, sign+validate (RSA/ECC)
- OCSP request implemented, active by default
- additional CertificateProfiles implemented

## Release 0.4.1

- resign test certificates

## Release 0.4.0

- refactoring:
  separate [TspInformationProvider](src/main/java/de/gematik/pki/tsl/TspInformationProvider.java)
  from
  [TslInformationProvider](src/main/java/de/gematik/pki/tsl/TslInformationProvider.java)
- OCSP request implemented, not used in certificate checks atm
- cleanup JavaDoc

## Release 0.3.0

- fix https://github.com/gematik/ref-GemLibPki/issues/1
- refactor class names

## Release 0.2.0

- accept several profiles/policies in certificates
- change behaviour of certificate checks (for [ext]KeyUsage) to fit gematik certificate profiles
- improve error logging in certificate checks
- fix KeyUsage in cert profile EGK
- rename enum CertificateProfiles to CertificateProfile
- encapsulate eu.europa.esig - lib uk ready now ;-)
- pump code coverage
- refactor packages

## Release 0.1.0

- This is the initial release of GemLibPki
- Certificate checks of TUC_PKI_018 are implemented
- see [README.md](README.md) for usage instructions and further information
