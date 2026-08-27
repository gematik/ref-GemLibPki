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

package de.gematik.pki.gemlibpki.commons.validators;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_ISSUER_CERT_QES_DEFAULT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static de.gematik.pki.gemlibpki.commons.error.ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.net.HttpURLConnection;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TucPki030OcspValidatorTest {

  private static final int OCSP_GRACE_PERIOD_10_SECONDS = 10;
  private static List<TspService> tspServiceListBNetzAVlDefault;
  private static List<TspService> tspServiceListBNetzAVlalternative;
  private static OcspResponderMock ocspResponderMock;

  private static OcspTransceiver getOcspTransceiver(
      final String ssp, final boolean tolerateOcspFailure) {
    return OcspTransceiver.builder()
        .productType(PRODUCT_TYPE)
        .x509EeCert(VALID_X509_EE_CERT_QES)
        .x509IssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
        .ssp(ssp)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }

  private void configureOcspResponderMockForOcspRequest(final Extension responseNonce) {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, responseNonce);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);
    ocspResponderMock.configureWireMockReceiveHttpPost(ocspResponse, HttpURLConnection.HTTP_OK);
  }

  @BeforeAll
  void setup() {
    tspServiceListBNetzAVlDefault = TestUtils.getDefaultTspServiceListQes();
    tspServiceListBNetzAVlalternative = TestUtils.getAlternativeTspServiceListQes();
    ocspResponderMock = OcspResponderMock.createAndStart(LOCAL_SSP_DIR, OCSP_HOST, null);
  }

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
  }

  /**
   * Call validateCertificate with a given OCSP response signed by the wrong signer and certificate
   * status GOOD. No transceiver is provided and not required for OCSP validation because OCSP
   * response could be fine. But the OCSP response is not valid because the signer is wrong.
   * Exception is expected because OCSP Transceiver is not provided.
   */
  @Test
  void
      validateCertificate_whenOcspSignerIsInvalidAndTransceiverIsMissing_thenThrowsGemPkiException() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlDefault)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThrows(
        NullPointerException.class,
        () -> tucPki030OcspValidator.validateCertificate(null, null, referenceDate));
    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  /**
   * Call validateCertificate with a given valid OCSP response and certificate status GOOD. No
   * transceiver is provided and not required because OCSP response is fine. The OCSP signer issuer
   * is in the alternative BNetzA-VL.
   */
  @Test
  void
      validateCertificate_whenOcspResponseIsValidAndSignerIssuerIsInAlternativeBNetzAVl_thenDoesNotThrow() {
    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponse(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes());

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlalternative)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    assertDoesNotThrow(
        () ->
            tucPki030OcspValidator.validateCertificate(
                VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsMonthsOldButTimestampsMatchReferenceDate_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC).minusMonths(6);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = referenceDate.plusSeconds(1);
    final ZonedDateTime nextUpdate = referenceDate.plusDays(1);

    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlalternative)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();

    assertDoesNotThrow(
        () ->
            tucPki030OcspValidator.validateCertificate(
                VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate));
  }

  @Test
  void validateCertificate_whenOcspProducedAtIsBeforeThisUpdate_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = thisUpdate.minusSeconds(1);
    final ZonedDateTime nextUpdate = referenceDate.plusSeconds(30);

    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlalternative)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  /**
   * Call validateCertificate with a given valid OCSP response and certificate status GOOD. No
   * transceiver is provided and not required because OCSP response is fine. The OCSP signer issuer
   * is NOT in the default BNetzA-VL, so fallback to the transceiver would be required. Because no
   * transceiver is provided, an OCSP_CHECK_REVOCATION_ERROR is expected.
   */
  @Test
  void
      validateCertificate_whenOcspSignerIssuerIsNotInDefaultBNetzAVlAndTransceiverIsMissing_thenThrowsGemPkiException() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlDefault)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsMissingAndTransceiverIsMissing_thenThrowsGemPkiException() {
    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlDefault)
            .withOcspCheck(true)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsMissingAndTransceiverReturnsMatchingNonce_thenDoesNotThrow() {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlalternative)
            .withOcspCheck(true)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertDoesNotThrow(
        () ->
            tucPki030OcspValidator.validateCertificate(
                VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, referenceDate, nonce));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsMissingAndTransceiverReturnsMismatchingNonce_thenThrowsGemPkiException() {
    final Extension expectedNonce = OcspRequestGenerator.generateNonceExtension();
    final Extension responseNonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(responseNonce);

    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlalternative)
            .withOcspCheck(true)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES,
                    VALID_ISSUER_CERT_QES_DEFAULT_CA,
                    referenceDate,
                    expectedNonce))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1051_OCSP_NONCE_MISMATCH.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenOcspCheckIsDisabledAndProducedAtToleranceIsNegative_thenDoesNotThrow() {
    final int invalidTolerance = -1;
    assertDoesNotThrow(
        () ->
            TucPki030OcspValidator.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceListBNetzAVl(tspServiceListBNetzAVlDefault)
                .ocspTimeToleranceProducedAtPastMilliseconds(invalidTolerance)
                .withOcspCheck(false)
                .build()
                .validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, ZonedDateTime.now()));
  }

  @Test
  void
      validateCertificate_whenOcspCheckIsEnabledAndProducedAtToleranceIsZero_thenThrowsGemPkiRuntimeException() {
    final int invalidTolerance = 0;
    final TucPki030OcspValidator tucPki030OcspValidator =
        TucPki030OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBNetzAVlDefault)
            .ocspTimeToleranceProducedAtPastMilliseconds(invalidTolerance)
            .withOcspCheck(true)
            .build();

    assertThatThrownBy(
            () ->
                tucPki030OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, ZonedDateTime.now()))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining("ocspTimeToleranceProducedAtPastMilliseconds must be greater than 0");
  }
}
