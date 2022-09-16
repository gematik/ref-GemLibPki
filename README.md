<img align="right" width="200" height="37" src="doc/images/Gematik_Logo_Flag.png"/> <br />

# GemLibPki

--- 
A java library for functionalities in PKI (Public Key Infrastructure) of products specified by gematik

---

Products specified by gematik which have to deal with PKI will have to handle certificates and
TSLs (TrustedServiceProvider Status List). This library may help to understand the intention of the
specification as a reference implementation.
Please
see [liability limitation](https://fachportal.gematik.de/default-titlegrundsaetzliche-nutzungsbedingungen)
for further information.

Specifications are published at [gematik Fachportal](https://fachportal.gematik.de/).

[Link to Maven Repository](https://mvnrepository.com/artifact/de.gematik.pki.gemlibpki/gemLibPki)

### Versioning

Versions below 1.0.0 are considered incomplete. API changes are possible and probable.

### Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
unit tests.
We are fully aware of the content and meaning of the test data. We never publish productive data.

### Content

##### Certificate checks

- we check against certificate profiles specified by gematik, not against usages and contexts
- we provide several methods to get information about a certificate and its issuer
- contains checks of all steps defined in TUC_PKI_018 „Zertifikatsprüfung in der TI“ specified in
  gematik document "Übergreifende Spezifikation PKI" (gemSpec_PKI)
- OCSP requests are optional and activated by default
- OCSP responses are verified according to TUC_PKI_006 "OCSP-Abfrage". See OCSP checks section.

##### OCSP checks

- OCSP responses can be generated with different properties. By default, a valid OCSP Response
  according to rf2560 is generated
- OCSP responses are validated according to TUC_PKI_006 of gemSpec_PKI.
- OCSP validation can be disabled via builder parameter `withOcspCheck` of
  [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/certificate/TucPki018Verifier.java).

##### TSL handling

- several methods for parsing, modifying, signing and signature validation of a TSL

##### Error codes

- error codes specified by gematik

### Build

The lib is developed and tested with **OpenJDK 17** and **Apache Maven 3.8.6**

Build with:

    mvn clean install

Builds are reproducible, to check call

    mvn clean verify artifact:compare

in any compatible unix environment.

### Steps to perform certificate checks

- instantiate a [TslReader](src/main/java/de/gematik/pki/gemlibpki/tsl/TslReader.java) to read a TSL
- use the result of the TslReader to instantiate
  a [TslInformationProvider](src/main/java/de/gematik/pki/gemlibpki/tsl/TslInformationProvider.java)
  and call its public methods
- get TspServices from TslInformationProvider
- instantiate
  a [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/certificate/TucPki018Verifier.java) (**
  via builder) and call its public method performTucPki18Checks

### Steps to perform TSL checks

- instantiate a [TslReader](src/main/java/de/gematik/pki/gemlibpki/tsl/TslReader.java) to read a TSL
- use the result of the TslReader to instantiate
  a [TslInformationProvider](src/main/java/de/gematik/pki/gemlibpki/tsl/TslInformationProvider.java)
  and call its public methods
- get TspServices from TslInformationProvider
- instantiate
  a [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java) (via
  builder) and call its
  public method performTucPki001Checks

### ToDo

- detailed TSL validation according to TUC_PKI_001
- implement critical extension checks according to GS-A_4661 (RFC5280#4.2)
