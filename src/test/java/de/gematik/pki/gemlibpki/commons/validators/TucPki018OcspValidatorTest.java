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
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.net.HttpURLConnection;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TucPki018OcspValidatorTest {

  private static final List<TspService> emptyTspServiceList = new ArrayList<>();
  private static final int OCSP_GRACE_PERIOD_10_SECONDS = 10;
  private static List<TspService> tspServiceList;
  private static OcspResponderMock ocspResponderMock;

  private static OcspTransceiver getOcspTransceiver(
      final String ssp, final boolean tolerateOcspFailure) {
    return OcspTransceiver.builder()
        .productType(PRODUCT_TYPE)
        .x509EeCert(VALID_X509_EE_CERT_SMCB)
        .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
        .ssp(ssp)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }

  private OCSPReq configureOcspResponderMockForOcspRequest() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    ocspResponderMock.configureForOcspRequest(
        ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    return ocspReq;
  }

  @BeforeAll
  public void setup() {
    ocspResponderMock = OcspResponderMock.createAndStart(LOCAL_SSP_DIR, OCSP_HOST, null);
    tspServiceList = TestUtils.getDefaultTspServiceListNonQes();
  }

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
  }

  /**
   * Call validateCertificate with given OCSP response with status success and certificate status
   * GOOD. No transceiver is provided and not required for OCSP validation because OCSP response is
   * fine.
   */
  @Test
  void
      validateCertificate_whenOcspResponseIsSuccessfulAndCertificateStatusIsGoodWithoutTransceiver_thenDoesNotThrow() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThrows(
        NullPointerException.class, () -> tucPki018OcspValidator.validateCertificate(null, null));
    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that given OCSP response was not cached
    assertThat(cache.getSize()).isZero();
  }

  /**
   * Check that OCSP grace period set in cache is equal to the
   * ocspToleranceProducedAtPastMilliseconds set in OcspValidator.
   */
  @Test
  void validateCertificate_whenOcspProducedAtToleranceIsZero_thenThrowsGemPkiRuntimeException() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    cache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResponse);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(0)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining("ocspTimeToleranceProducedAtPastMilliseconds must be greater than 0");
  }

  /**
   * Call validateCertificate with given OCSP response with response status unauthorized. No
   * transceiver is provided, but is actually required in this case.
   */
  @Test
  void
      validateCertificate_whenOcspResponseStatusIsUnauthorizedAndTransceiverIsMissing_thenThrowsGemPkiException() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .respStatus(OCSPRespStatus.UNAUTHORIZED)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));

    // check that given (bad) OCSP response was not cached
    assertThat(cache.getSize()).isZero();
  }

  /**
   * Call validateCertificate with given OCSP response with response status success and cert status
   * revoked since a few seconds ago. Referece time is before the revocation time.
   */
  @Test
  void
      validateCertificate_whenOcspResponseReportsRevocationAfterReferenceDate_thenDoesNotThrowBeforeRevocationAndThrowAfterRevocation() {
    final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime producedAt = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime nextUpdate = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(30);
    final ZonedDateTime revocationTime = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(15);
    final ZonedDateTime referenceTime = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(30);

    final OcspRespCache ocspRespCache = new OcspRespCache(30);

    final OCSPResp ocspResp =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_SMCB,
            VALID_ISSUER_CERT_SMCB,
            OcspTestConstants.getOcspSignerEccNonQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            new RevokedStatus(Date.from(revocationTime.toInstant()), CRLReason.privilegeWithdrawn));

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResp)
            .ocspRespCache(ocspRespCache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceTime));

    // reference time is after the revocation time, so the certificate is revoked
    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(
                    VALID_X509_EE_CERT_SMCB, ZonedDateTime.now(ZoneOffset.UTC)))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsMonthsOldButTimestampsMatchReferenceDate_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC).minusMonths(6);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = referenceDate.plusSeconds(1);
    final ZonedDateTime nextUpdate = referenceDate.plusDays(1);

    final OCSPResp ocspResp =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_SMCB,
            VALID_ISSUER_CERT_SMCB,
            OcspTestConstants.getOcspSignerEccNonQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResp)
            .ocspRespCache(new OcspRespCache(30))
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  @Test
  void validateCertificate_whenOcspProducedAtIsBeforeThisUpdate_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = thisUpdate.minusSeconds(1);
    final ZonedDateTime nextUpdate = referenceDate.plusSeconds(30);

    final OCSPResp ocspResp =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_SMCB,
            VALID_ISSUER_CERT_SMCB,
            OcspTestConstants.getOcspSignerEccNonQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResp)
            .ocspRespCache(new OcspRespCache(30))
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  /**
   * Call validateCertificate with given OCSP response with response status unauthorized. A
   * transceiver is provided and is expected to provide a valid OCSP response.
   */
  @Test
  void
      validateCertificate_whenInitialOcspResponseStatusIsUnauthorizedAndTransceiverReturnsValidResponse_thenDoesNotThrow() {

    final OCSPReq ocspReqDefault = configureOcspResponderMockForOcspRequest();
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .respStatus(OCSPRespStatus.UNAUTHORIZED)
            .build()
            .generate(ocspReqDefault, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspResponse(ocspResponse)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspRespCache(cache)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that received OCSP response was cached
    assertThat(cache.getSize()).isEqualTo(1);
  }

  /**
   * Call validateCertificate with cached OCSP response with status success and certificate status
   * GOOD. An empty tspServiceList and no transceiver are provided and not required for OCSP
   * validation because OCSP response in cache is fine.
   */
  @Test
  void
      validateCertificate_whenCachedOcspResponseIsSuccessfulAndCertificateStatusIsGood_thenDoesNotThrow() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    cache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResponse);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(emptyTspServiceList)
            .withOcspCheck(true)
            .ocspResponse(null)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(null)
            .tolerateOcspFailure(false)
            .build();
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  @Test
  void validateCertificate_whenTransceiverReturnsSuccessfulOcspResponse_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that received OCSP response was cached
    assertThat(cache.getSize()).isEqualTo(1);
  }

  @Test
  void
      validateCertificate_whenTransceiverReturnsOcspResponseWithUnknownStatus_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .respStatus(OCSPRespStatus.UNKNOWN_STATUS)
            .build()
            .generate(
                ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, CertificateStatus.GOOD);

    ocspResponderMock.configureWireMockReceiveHttpPost(ocspResp, HttpURLConnection.HTTP_OK);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1058_OCSP_STATUS_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validateCertificate_whenCacheIsEmptyAndTspServiceListIsEmpty_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(emptyTspServiceList)
            .withOcspCheck(true)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_10_SECONDS * 1000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(
            () ->
                tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenOcspResponseIsCachedWithGracePeriod_thenRemovesExpiredResponseFromCache() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(2);

    final TucPki018OcspValidator tucPki018OcspValidator =
        TucPki018OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspRespCache(cache)
            .ocspTimeToleranceProducedAtPastMilliseconds(2000)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();

    assertDoesNotThrow(
        () -> tucPki018OcspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that received OCSP response was cached
    assertThat(cache.getSize()).isEqualTo(1);
    TestUtils.waitSeconds(cache.getOcspGracePeriodSeconds() + 1);
    // check that cached OCSP response was deleted after grace period
    final Optional<OCSPResp> ocspRespOpt =
        cache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber());
    assertThat(ocspRespOpt).isEmpty();
    assertThat(cache.getSize()).isZero();
  }
}
