<img align="right" width="250" height="47" src="doc/images/Gematik_Logo_Flag_With_Background.png"/> <br/>

# Release notes GemLibPki

## Release 2.1.1

- update dependencies

## Release 2.1.0

- change the order of the elements in the subjectDN of the ocsp responder id
- add test to verify NIST curve support
- update DSS Lib and tidy up dependencies
- update dependencies

## Release 2.0.3

- update tsl signer
- add CRL service type identifier
- new certificate types C.HSK.SIG and C.HSK.ENC
- new OID SM-B NCPeH
- update dependencies

## Release 2.0.2

- refactor code for better readability
- bump bouncy castle

## Release 2.0.1

- introduce validation interface to encapsulate validation
  steps https://github.com/gematik/ref-GemLibPki/pull/7
- add NONCE extension to OCSP response if it existed in request
- refactor code for better readability
- add gitHub templates for issues and pull requests
- update dependencies

## Release 1.3.0

- add missing OIDs from gem_Spec_OID for different roles
- add method to check the profession oid in the returned admission of a certificate:
  `TucPki018Verifier.checkAllowedProfessionOids()`
- update soon expiring unit test certificates
- update dependencies

## Release 1.2.0

- introduce a generic enum (`CertificateProfile.CERT_PROFILE_ANY`) to allow any certificate profile
  for TUC_PKI_018 checks. The usage of this certificate profile disables the checks of keyUsage,
  extendedKeyUsage, and certificateTypeOids. This should resolve
  issue https://github.com/gematik/ref-GemLibPki/issues/3.
- remove log messages that reveal personal information
- update dependencies

## Release 1.1.0

- API change: rename some methods that provide a TSL and deliver unsigned content
- API change: rename method `performTucPki18Checks` to `performTucPki018Checks` to match name from
  specification
- API change: rename method `performOcspChecks` to `performTucPki006Checks` to match name from
  specification
- API change: method `performTucPki006Checks()` does not need the OCSP requests anymore because of
  change in certId checks
- change behavior of certId checks in OCSP responses: it is calculated from announced hash
  algorithm and compared to the fields of the response
- change default behavior of certId OCSP response generation: the algorithm used is mirrored by the
  algorithm used in the OCSP request, this can be overwritten with the `responseAlgoBehavior`
  builder parameter via an enum
- introduce handling of SHA256 hashes in OCSP context (certId)
- add TLS-S and TLS-C certificate profiles to solve
  issue https://github.com/gematik/ref-GemLibPki/issues/3
- update dependencies

## Release 1.0.0

- API change: harmonize variable names like tslSeqNr
- add static method to check validity of the current TSL: `verifyTslValidity()`
  in [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java)
- add tests of critical extensions according to RFC5280#4.2
  in [CertificateProfileVerification](src/main/java/de/gematik/pki/gemlibpki/certificate/CertificateProfileVerification.java)
- add tsl xml well-formed test
  in [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java)
- rework some code for better readability
- increase code coverage
- update dependencies

## Release 0.12.0

- add scheme validation tests
  in [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java)
- add missing certificate types
- add some convenience methods
- update test data
- update dependencies

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

- change language-specific code (>Java 11)
- fix small issues

## Release 0.8.0

- API change: move the whole package from de.gematik.pki to de.gematik.pki.gemlibpki
- usage of BouncyCastle as crypto provider is enforced in every class/method that deals with
  brainpool curves
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
- refactor OcspVerifier class to harmonize with CertificateVerifier

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
  of CertificateType.
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
