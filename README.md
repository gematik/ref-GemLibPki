<img align="right" width="250" height="47" src="doc/images/Gematik_Logo_Flag_With_Background.png"/> <br/>

# GemLibPki

--- 
<img align="left" height="150" src="doc/images/logo.svg" />

A java library for functionalities in PKI (Public Key Infrastructure) of products specified by
gematik.

Products specified by gematik which have to deal with PKI will have to handle certificates and
TSLs (TrustedServiceProvider Status List). This library may help to understand the intention of the
specification as a reference implementation.
Please
see [liability limitation](https://fachportal.gematik.de/default-titlegrundsaetzliche-nutzungsbedingungen)
for further information.

* QES handling is not a part of this library.
* Specifications are published at [gematik Fachportal](https://fachportal.gematik.de/).
* [Link to Maven Repository](https://mvnrepository.com/artifact/de.gematik.pki/gemLibPki)

---

### Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
unit tests.
We are fully aware of the content and meaning of the test data. We never publish productive data
willingly.

### Content

##### Certificate checks

For certificate checks the library offers interfaces:

- [CertificateValidator.java](src%2Fmain%2Fjava%2Fde%2Fgematik%2Fpki%2Fgemlibpki%2Fvalidators%2FCertificateValidator.java)
- [CertificateProfileValidator.java](src%2Fmain%2Fjava%2Fde%2Fgematik%2Fpki%2Fgemlibpki%2Fvalidators%2FCertificateProfileValidator.java)

as well as a couple of implementations for different checks alongside
(see [validators](src%2Fmain%2Fjava%2Fde%2Fgematik%2Fpki%2Fgemlibpki%2Fvalidators)). You can build a
chain of different checks or extend the library for your own requirements.

###### TUC_PKI_018 - Zertifikatsprüfung in der TI

A complete implementation of the TUC_PKI_018 „Zertifikatsprüfung in der TI“ of the gematik
document "Übergreifende Spezifikation PKI" (gemSpec_PKI)can be found
in [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/certificate/TucPki018Verifier.java)
Here we check against nonQES certificate profiles specified by gematik, not against usages and
contexts (a special certificate profile for allowing any profile, i.e., disable profile checks is
available as well)

OCSP requests are optional and activated by default. OCSP responses are verified according to
TUC_PKI_006 "OCSP-Abfrage"
(see [OCSP checks](./README.md#ocsp-checks) section).

For examples of how to use the TUC_PKI_018 implementation
see [TucPki018VerifierTest.java](src%2Ftest%2Fjava%2Fde%2Fgematik%2Fpki%2Fgemlibpki%2Fcertificate%2FTucPki018VerifierTest.java)

##### OCSP checks

OCSP responses can be generated with different properties. By default, a valid OCSP response,
according to rf2560, is generated. OCSP responses are validated according to TUC_PKI_006 of
gemSpec_PKI.

OCSP validation can be disabled via builder parameter `withOcspCheck` of
[TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/certificate/TucPki018Verifier.java).

##### TSL handling

The library contains checks defined in TUC_PKI_001 „Periodische Aktualisierung TI-Vertrauensraum“
specified in gematik document "Übergreifende Spezifikation PKI" (gemSpec_PKI)

We provide several methods to get information, for parsing, modifying, signing and validation of a
TSL. (see: [TSL package](src/main/java/de/gematik/pki/gemlibpki/tsl))

Attention: the trust anchor change mechanism is not completely implemented in this library,
because it has to be part of the TSL downloading component. An example of an implementation
can be found in the system under test simulator of the gematik PKI test
suite: [TslProcurer](https://github.com/gematik/app-PkiTestsuite/blob/1.1.3/pkits-sut-server-sim/src/main/java/de/gematik/pki/pkits/sut/server/sim/tsl/TslProcurer.java)

###### Steps to perform TSL checks

- instantiate a [TslReader](src/main/java/de/gematik/pki/gemlibpki/tsl/TslReader.java) to read a TSL
- use the result of the TslReader to instantiate
  a [TslInformationProvider](src/main/java/de/gematik/pki/gemlibpki/tsl/TslInformationProvider.java)
  and call its public methods
- get TspServices from TslInformationProvider
- instantiate
  a [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/tsl/TucPki001Verifier.java) (via
  builder) and call its public method `performTucPki001Checks()`
- the offline mode for TUC_PKI_001 (used solely for a Konnektor) is not implemented

##### Error codes

- error codes specified by gematik in gemSpec_PKI

### Build

The lib is developed and tested
with [Eclipse Adoptium Temurin JDK 17](https://github.com/adoptium/temurin17-binaries) and [Apache
Maven 3.9.3](https://maven.apache.org/index.html)

Build with:

```bash
mvn clean install
```

Builds are reproducible, to check call

```bash
mvn clean verify artifact:compare
```

in any compatible unix environment.

## License

Copyright 2023 gematik GmbH

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License.

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under
the License.

Unless required by applicable law the software is provided "as is" without warranty of any kind,
either express or implied, including, but not limited to, the warranties of fitness for a particular
purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be
liable in any manner whatsoever for any damages or other claims arising from, out of or in
connection with the software or the use or other dealings with the software, whether in an action of
contract, tort, or otherwise.

The software is the result of research and development activities, therefore not necessarily quality
assured and without the character of a liable product. For this reason, gematik does not provide any
support or other user assistance (unless otherwise stated in individual cases and without
justification of a legal obligation). Furthermore, there is no claim to further development and
adaptation of the results to a more current state of the art.

Gematik may remove published results temporarily or permanently from the place of publication at any
time without prior notice or justification.
