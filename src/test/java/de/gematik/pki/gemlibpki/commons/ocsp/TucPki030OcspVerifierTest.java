/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.commons.ocsp;

import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_ISSUER_CERT_QES_DEFAULT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.Test;

class TucPki030OcspVerifierTest {

  @Test
  void
      verifyOcspResponseSignature_whenSignerCertificateDoesNotMatchSignature_thenThrowsGemPkiException() {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES;
    final TucPki030OcspVerifier tucPki030OcspVerifier =
        TucPki030OcspVerifier.builder()
            .productType("TestProduct")
            .tspServiceListBNetzAVl(List.of())
            .eeCert(eeCert)
            .eeCertIssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
            .ocspResponse(
                TestUtils.generateOcspResponse(
                    eeCert, VALID_ISSUER_CERT_QES_DEFAULT_CA, OcspTestConstants.getOcspSignerQes()))
            .build();

    final X509Certificate notTheOcspSignerCert = VALID_ISSUER_CERT_QES_DEFAULT_CA;

    assertThatThrownBy(
            () -> tucPki030OcspVerifier.verifyOcspResponseSignature(notTheOcspSignerCert))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR.getErrorTextShort());
  }

  @Test
  void performOcspChecks_whenOcspSignerCertificateIsInBNetzAVl_thenDoesNotThrow() {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES;
    final TucPki030OcspVerifier tucPki030OcspVerifier =
        TucPki030OcspVerifier.builder()
            .productType("TestProduct")
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalOcspSignerDefaultTslUnsignedQes())
                    .getTspServices())
            .eeCert(eeCert)
            .eeCertIssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
            .ocspResponse(
                TestUtils.generateOcspResponse(
                    eeCert, VALID_ISSUER_CERT_QES_DEFAULT_CA, OcspTestConstants.getOcspSignerQes()))
            .build();

    assertDoesNotThrow(
        () -> tucPki030OcspVerifier.performOcspChecks(ZonedDateTime.now(ZoneOffset.UTC)));
  }

  @Test
  void performOcspChecks_whenNonceMatches_thenDoesNotThrow() {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES;
    final Extension responseNonce = OcspRequestGenerator.generateNonceExtension();
    final TucPki030OcspVerifier tucPki030OcspVerifier =
        TucPki030OcspVerifier.builder()
            .productType("TestProduct")
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalOcspSignerDefaultTslUnsignedQes())
                    .getTspServices())
            .eeCert(eeCert)
            .eeCertIssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
            .ocspResponse(
                TestUtils.generateOcspResponse(
                    eeCert,
                    VALID_ISSUER_CERT_QES_DEFAULT_CA,
                    OcspTestConstants.getOcspSignerQes(),
                    responseNonce))
            .nonce(responseNonce)
            .build();

    assertDoesNotThrow(
        () -> tucPki030OcspVerifier.performOcspChecks(ZonedDateTime.now(ZoneOffset.UTC)));
  }

  @Test
  void performOcspChecks_whenCertStatusUnknown_thenThrowsGemPkiException() {
    final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime producedAt = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime nextUpdate = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(30);

    final X509Certificate eeCert = VALID_X509_EE_CERT_QES;
    final Extension responseNonce = OcspRequestGenerator.generateNonceExtension();
    final TucPki030OcspVerifier tucPki030OcspVerifier =
        TucPki030OcspVerifier.builder()
            .productType("TestProduct")
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalOcspSignerDefaultTslUnsignedQes())
                    .getTspServices())
            .eeCert(eeCert)
            .eeCertIssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
            .ocspResponse(
                TestUtils.generateOcspResponseWithTimeStamps(
                    eeCert,
                    VALID_ISSUER_CERT_QES_DEFAULT_CA,
                    OcspTestConstants.getOcspSignerQes(),
                    responseNonce,
                    thisUpdate,
                    producedAt,
                    nextUpdate,
                    new UnknownStatus()))
            .nonce(responseNonce)
            .build();

    assertThatThrownBy(
            () -> tucPki030OcspVerifier.performOcspChecks(ZonedDateTime.now(ZoneOffset.UTC)))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.TW_1044_CERT_UNKNOWN.getErrorTextShort());
  }

  @Test
  void performOcspChecks_whenNonceMismatches_thenThrowsGemPkiException() {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES;
    final Extension responseNonce = OcspRequestGenerator.generateNonceExtension();
    final TucPki030OcspVerifier tucPki030OcspVerifier =
        TucPki030OcspVerifier.builder()
            .productType("TestProduct")
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalOcspSignerDefaultTslUnsignedQes())
                    .getTspServices())
            .eeCert(eeCert)
            .eeCertIssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
            .ocspResponse(
                TestUtils.generateOcspResponse(
                    eeCert,
                    VALID_ISSUER_CERT_QES_DEFAULT_CA,
                    OcspTestConstants.getOcspSignerQes(),
                    responseNonce))
            .nonce(OcspRequestGenerator.generateNonceExtension())
            .build();

    assertThatThrownBy(
            () -> tucPki030OcspVerifier.performOcspChecks(ZonedDateTime.now(ZoneOffset.UTC)))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1051_OCSP_NONCE_MISMATCH.getErrorTextShort());
  }
}
