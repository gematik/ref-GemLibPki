# ![Logo](./doc/images/certification_64px.png) GemLibPki
<div>Icons made by <a href="https://www.freepik.com" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>

## GemLibPki - a Java library for functionalities in PKI (Public Key Infrastructure) of products specified by gematik
Products specified by gematik which have to deal with PKI will have to handle certificates and TSLs (TrustedServiceProvider Status List).
This library may help to understand the intention of specification and could be useful for software implementations.

Specifications are published at [Gematik Fachportal](https://fachportal.gematik.de/).

### Version
Versions below 1.0.0 are not feature complete.

### Content
##### Certificate checks
- we check against certificate profiles specified by gematik, not against usages and contexts
- several methods to get information about a certificate and its issuer
- contains checks of all steps defined in TUC_PKI_018 „Zertifikatsprüfung in der TI“ specified in gematik document "Übergreifende Spezifikation PKI" (gemSpec_PKI)
- OCSP requests are optional and activated by default
- OCSP response are not analyzed beyond status GOOD (nor signature checking etc.)

##### TSL handling
- several methods for parsing, modifying, signing and signature validation of a TSL

##### OCSP
- signed OCSP responses can be generated, but always with status GOOD

##### Error codes
- error codes specified by gematik

### Build
mvn clean install

### Steps to perform certificate checks
- instantiate a [TslReader](src/main/java/de/gematik/pki/tsl/TslReader.java) to read a TSL
- use the result of the TslReader to instantiate a [TslInformationProvider](src/main/java/de/gematik/pki/tsl/TslInformationProvider.java) and simply call its public methods
- get TspServices from TslInformationProvider
- instantiate a [TucPki018Verifier](src/main/java/de/gematik/pki/certificate/TucPki018Verifier.java) (via builder) and simply call its public method performTucPki18Checks

### ToDo
- detailed TSL validation according to TUC_PKI_001
- detailed OCSP validation according to TUC_PKI_006
- implement critical extension checks according to GS-A_4661 (RFC5280#4.2)
