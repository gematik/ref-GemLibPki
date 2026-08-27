<img align="right" width="250" src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png"/> <br/> 

[![GitHub Latest Release](https://img.shields.io/github/v/release/gematik/ref-GemLibPki?label=release&logo=github)](https://github.com/gematik/ref-GemLibPki) [![Maven Central](https://img.shields.io/maven-central/v/de.gematik.pki/gemLibPki.svg)](https://search.maven.org/artifact/de.gematik.pki/gemLibPki) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# GemLibPki

<img align="left" height="150" src="doc/images/logo.svg" />

## About The Project

A java library for functionalities in PKI (Public Key Infrastructure) of products specified by
gematik.

Products specified by gematik which have to deal with PKI will have to handle certificates and TSLs
(TrustedServiceProvider Status Lists)/ BNetzA-VL (Bundesnetzagentur-Vertrauensliste). This library
may help to understand the intention of the specification as a reference implementation. Please
see [liability limitation](https://fachportal.gematik.de/default-titlegrundsaetzliche-nutzungsbedingungen)
for further information.

* Specifications are published at [gematik Fachportal](https://fachportal.gematik.de/).

## Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) for all information regarding the (newest) releases.

## Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
unit tests. We are fully aware of the content and meaning of the test data. We never publish
productive data willingly.

## Content

### Certificate checks

For certificate checks the library offers interfaces:

- [CertificateValidator.java](src/main/java/de/gematik/pki/gemlibpki/commons/validators/CertificateValidator.java)
- [CertificateProfileValidator.java](src/main/java/de/gematik/pki/gemlibpki/commons/validators/CertificateProfileValidator.java)

as well as a couple of implementations for different checks alongside
(see [validators](src/main/java/de/gematik/pki/gemlibpki/commons/validators)). You can build a chain
of different checks or extend the library for your own requirements.

#### TUC_PKI_018 - Zertifikatsprüfung in der TI

A complete implementation of the TUC_PKI_018 „Zertifikatsprüfung in der TI“ of the gematik document
"Übergreifende Spezifikation PKI" (gemSpec_PKI)can be found
in [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/TucPki018Verifier.java)
Here we check against nonQES certificate profiles specified by gematik, not against usages and
contexts (a special certificate profile for allowing any profile, i.e., disable profile checks is
available as well)

OCSP requests are optional and activated by default. OCSP responses are verified according to
TUC_PKI_006 "OCSP-Abfrage"
(see [OCSP checks](./README.md#ocsp-checks) section).

For examples of how to use the TUC_PKI_018 implementation
see [TucPki018VerifierTest.java (TI 1.0)](src/test/java/de/gematik/pki/gemlibpki/commons/certificate/TucPki018VerifierTest.java).

#### TUC_PKI_030 - QES-Zertifikatsprüfung

An implementation of TUC_PKI_030 „QES-Zertifikatsprüfung“ can be found in
[TucPki030Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/tuc030/TucPki030Verifier.java).

The current implementation focuses on the validation of QES end-entity certificates. It checks the
presence of the required QC statement, certificate validity, the expected KeyUsage, the matching
QES-CA in the BNetzA-VL, the qualification and status of that QES-CA and the mathematical signature
of the certificate chain based on the certificate issuance date.

OCSP checks are supported as part of TUC_PKI_030 and are enabled by default. The corresponding
implementation can be found in
[TucPki030OcspVerifier](src/main/java/de/gematik/pki/gemlibpki/commons/ocsp/TucPki030OcspVerifier.java)
and [TucPki030OcspValidator](src/main/java/de/gematik/pki/gemlibpki/commons/validators/TucPki030OcspValidator.java).

For examples of how to use the current TUC_PKI_030 implementation
see [TucPki030VerifierTest.java](src/test/java/de/gematik/pki/gemlibpki/commons/certificate/tuc030/TucPki030VerifierTest.java).

### OCSP checks

OCSP responses can be generated with different properties. By default, a valid OCSP response,
according to rf2560, is generated. OCSP responses are validated according to TUC_PKI_006 of
gemSpec_PKI. There are the following deviations from the specification. To allow OCSP responses that
are, for example, months old, only plausibility checks are performed on the `thisUpdate` and
`producedAt` timestamps:

1. `thisUpdate` must not be more than the specified tolerance in the future.
2. `producedAt` must not be more than the set tolerance in the future.
3. `thisUpdate` must not be later than `producedAt`.

OCSP validation can be disabled via builder parameter `withOcspCheck` of
[TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/TucPki018Verifier.java)
or
[TucPki030Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/tuc030/TucPki030Verifier.java).

The location of the OCSP SSP (service supply point - address of the OCSP responder) is different for
TI 1.0 and TI 2.0 (TI = Telematik Infrastruktur). The
Interface [OcspTransceiverFactory](src/main/java/de/gematik/pki/gemlibpki/commons/ocsp/OcspTransceiverFactory.java)
will take care of it. There following implementations of this interface exist:

#### TI 1.0:

nonQES: </br>
The SSP is expected to be listed in the TSL, in the entry for the CA of the certificate.
The [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/TucPki018Verifier.java)
will use
the [TslBasedSspOcspTransceiverFactory](src/main/java/de/gematik/pki/gemlibpki/ti10/ocsp/TslBasedSspOcspTransceiverFactory.java)
as default and everything works as it did before TI 20 started.

QES: </br>
The SSP is located on the internet and is therefore expected to be listed in the Extensions of the
certificate itself. But it can be overridden by the TSL entry for the CA of the certificate.
The [TucPki030Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/tuc030/TucPki030Verifier.java)
will use
the [TucPki30OcspTransceiverFactory](src/main/java/de/gematik/pki/gemlibpki/ti10/ocsp/TucPki030OcspTransceiverFactory.java)
as default.

#### TI 2.0:

The SSP is located on the internet and is therefore expected to be listed in the Extensions of the
certificate itself. There it is the Extension `AuthorityInformationAccess`.
The [TucPki018Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/certificate/TucPki018Verifier.java)
needs
a [CertificateBasedSspOcspTransceiverFactory](src/main/java/de/gematik/pki/gemlibpki/ti20/ocsp/CertificateBasedSspOcspTransceiverFactory.java)
and this will do the work.

Examples can be found in the unit tests.

### TSL handling

There are two different types of trust lists. They contain either QES certificates (BNetzA-VL) or
non-QES certificates (TSL). From version 5.0.1 this library is able to handle both trust lists,
except a TucPki036Verifier for QES (equivalent to TucPki001Verifier for nonQES) will be implemented
later.

For nonQES, the library contains checks defined in TUC_PKI_001 „Periodische Aktualisierung
TI-Vertrauensraum“ specified in gematik document "Übergreifende Spezifikation PKI" (gemSpec_PKI).

We provide several methods to get information, for parsing, modifying, signing and validation of a
TSL (see: [TSL package](src/main/java/de/gematik/pki/gemlibpki/commons/tsl)).

Attention: the trust anchor change mechanism is not completely implemented in this library, because
it has to be part of the TSL downloading component. An example of an implementation can be found in
the `system under test simulator` of the gematik PKI test suite,
component: [TslProcurer](https://github.com/gematik/app-PkiTestsuite/blob/main/pkits-sut-server-sim/src/main/java/de/gematik/pki/pkits/sut/server/sim/tsl/TslProcurer.java).

#### Steps to perform trust list checks

- instantiate a [TslReader](src/main/java/de/gematik/pki/gemlibpki/commons/tsl/TslReader.java) to
  read a TSL
- use the result of the TslReader to instantiate
  a [TslInformationProvider](src/main/java/de/gematik/pki/gemlibpki/commons/tsl/TslInformationProvider.java)
  and call its public methods
- get TspServices from TslInformationProvider
- for nonQES instantiate
  a [TucPki001Verifier](src/main/java/de/gematik/pki/gemlibpki/commons/tsl/TucPki001Verifier.java)
  (via builder) and call its public method `performTucPki001Checks()`. The offline mode for
  TUC_PKI_001 (used solely for a Konnektor) is not implemented
- for QES instantiate ... tbd

### Error codes

- error codes specified by gematik in gemSpec_PKI

### Build

Build with:

```bash
mvn clean install
```

## License

Copyright 2020-2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under
the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the
   license conditions for use. These are regularly typical conditions in connection with open source
   or free software. Programs described/provided/linked here are free software, unless otherwise
   stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal in the Software
   without restriction, including without limitation the rights to use, copy, modify, merge,
   publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to
   whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all
       copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied,
       including, but not limited to, the warranties of fitness for a particular purpose,
       merchantability, and/or non-infringement. The authors or copyright holders shall not be
       liable in any manner whatsoever for any damages or other claims arising from, out of or in
       connection with the software or the use or other dealings with the software, whether in an
       action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily
       quality assured and without the character of a liable product. For this reason, gematik does
       not provide any support or other user assistance (unless otherwise stated in individual cases
       and without justification of a legal obligation). Furthermore, there is no claim to further
       development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at
   any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please
   take this into account, especially when troubleshooting, for security analyses and possible
   adjustments.

