/*
 * Copyright 2024 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.validators;

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.net.HttpURLConnection;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspValidatorTest {

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
  public static void start() {
    ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    tspServiceList = TestUtils.getDefaultTspServiceList();
  }

  /**
   * Call validateCertificate with given OCSP response with status success and certificate status
   * GOOD. No transceiver is provided and not required for OCSP validation because OCSP response is
   * fine.
   */
  @Test
  void
      test_validateCertificate_GivenOcspResp_RespStatusSuccess_CertStatusGood_withoutTransceiver() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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

    assertThrows(NullPointerException.class, () -> ocspValidator.validateCertificate(null, null));
    assertDoesNotThrow(
        () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that given OCSP response was not cached
    assertThat(cache.getSize()).isZero();
  }

  /**
   * Check that OCSP grace period set in cache is equal to the
   * ocspToleranceProducedAtPastMilliseconds set in OcspValidator.
   */
  @Test
  void
      test_validateCertificate_GivenOcspResp_RespStatusSuccess_CertStatusGood_toleranceMisconfiguration() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    cache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResponse);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
            () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining("ocspTimeToleranceProducedAtPastMilliseconds must be greater than 0");
  }

  /**
   * Call validateCertificate with given OCSP response with response status unauthorized. No
   * transceiver is provided, but is actually required in this case.
   */
  @Test
  void test_validateCertificate_GivenOcspResp_RespStatusSuccess_CertStatusBad_withoutTransceiver() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .respStatus(OCSPRespStatus.UNAUTHORIZED)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
            () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("\"this.ocspTransceiver\" is null");

    // check that given (bad) OCSP response was not cached
    assertThat(cache.getSize()).isZero();
  }

  /**
   * Call validateCertificate with given OCSP response with response status unauthorized. A
   * transceiver is provided and is expected to provide a valid OCSP response.
   */
  @Test
  void test_validateCertificate_GivenOcspResp_RespStatusBad_CertStatusGood_withTransceiver() {

    final OCSPReq ocspReqDefault = configureOcspResponderMockForOcspRequest();
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .respStatus(OCSPRespStatus.UNAUTHORIZED)
            .build()
            .generate(ocspReqDefault, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
        () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

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
      test_validateCertificate_CachedOcspResp_RespStatusSuccess_CertStatusGood_withoutTransceiver() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);
    cache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResponse);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
        () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  @Test
  void test_validateCertificate_ReceiveOcspResp_RespStatusSuccess_CertStatusGood() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
        () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

    // check that received OCSP response was cached
    assertThat(cache.getSize()).isEqualTo(1);
  }

  @Test
  void test_validateCertificate_ReceiveOcspResp_RespStatusBad_CertStatusGood_withoutCache() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .respStatus(OCSPRespStatus.UNKNOWN_STATUS)
            .build()
            .generate(
                ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, CertificateStatus.GOOD);

    ocspResponderMock.configureWireMockReceiveHttpPost(ocspResp, HttpURLConnection.HTTP_OK);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .withOcspCheck(true)
            .ocspTimeoutSeconds(DEFAULT_OCSP_TIMEOUT_SECONDS)
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl(), false))
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(
            () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1058_OCSP_STATUS_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void test_exception_emptycache_emptyTspServiceList() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(OCSP_GRACE_PERIOD_10_SECONDS);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
            () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      test_validateCertificate_ReceiveOcspResp_RespStatusSuccess_CertStatusGood_CacheAppliesGracePeriod() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(2);

    final OcspValidator ocspValidator =
        OcspValidator.builder()
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
        () -> ocspValidator.validateCertificate(VALID_X509_EE_CERT_SMCB, referenceDate));

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
