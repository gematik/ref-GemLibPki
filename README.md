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

##### TSL handling
- several methods for parsing a TSL

##### Error codes
- error codes specified by gematik

### Build
mvn clean install

### Usage
##### Certificate checks
- instantiate an TucPki018Verifier (via builder) and simply call its public method performTucPki18Checks
##### TSL
- instantiate a TslReader to read a TSL from a resource
- use the result of the TslReader to instantiate a TslInformationProvider and simply call its public methods

### ToDo
* OCSP status requests
* download and validation of the trust services list (TSL)
