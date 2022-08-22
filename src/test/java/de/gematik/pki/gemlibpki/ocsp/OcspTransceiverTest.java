/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.ocsp.OcspTransceiver.OCSP_SEND_RECEIVE_FAILED;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspTransceiverTest {

  private static List<TspService> tspServiceList;

  private static X509Certificate VALID_X509_EE_CERT;
  private static X509Certificate VALID_X509_ISSUER_CERT;
  private static OcspResponderMock ocspResponderMock;

  private static final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @BeforeAll
  public static void start() {
    ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    VALID_X509_ISSUER_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");

    tspServiceList = TestUtils.getDefaultTspServiceList();
  }

  @Test
  void verifyOcspStatusExpectedGood() {
    configureOcspResponderMockForOcspRequest();

    assertDoesNotThrow(() -> getOcspTransceiver().verifyOcspResponse(null));
  }

  private static OcspTransceiver getOcspTransceiver() {
    return OcspTransceiver.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .x509EeCert(VALID_X509_EE_CERT)
        .x509IssuerCert(VALID_X509_ISSUER_CERT)
        .ssp(ocspResponderMock.getSspUrl())
        .ocspTimeoutSeconds(ocspTimeoutSeconds)
        .build();
  }

  @Test
  void verifyOcspStatusExpectedGoodFromCache() {

    configureOcspResponderMockForOcspRequest();

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerRsa())
            .build()
            .generate(
                OcspRequestGenerator.generateSingleOcspRequest(
                    VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT),
                VALID_X509_EE_CERT);
    final OcspRespCache cache = new OcspRespCache(10);
    cache.saveResponse(VALID_X509_EE_CERT.getSerialNumber(), ocspResp);

    assertDoesNotThrow(
        () ->
            OcspTransceiver.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .x509EeCert(VALID_X509_EE_CERT)
                .x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp("http://invalid.url") // to see, if cached response is used
                .build()
                .verifyOcspResponse(cache));
  }

  @Test
  void verifyOcspStatusExpectedGoodAutoSavedToCache() throws GemPkiException {

    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(10);

    getOcspTransceiver().verifyOcspResponse(cache);

    assertDoesNotThrow(
        () ->
            OcspTransceiver.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .x509EeCert(VALID_X509_EE_CERT)
                .x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp("http://invalid.url") // to see, if cached response is used
                .build()
                .verifyOcspResponse(cache));
  }

  @Test
  void verifyOcspStatusExpectedGoodNotSavedToCache() {

    configureOcspResponderMockForOcspRequest();

    final OcspRespCache cache = new OcspRespCache(10);

    assertThatThrownBy(
            () ->
                OcspTransceiver.builder()
                    .productType(PRODUCT_TYPE)
                    .tspServiceList(tspServiceList)
                    .x509EeCert(VALID_X509_EE_CERT)
                    .x509IssuerCert(VALID_X509_ISSUER_CERT)
                    .ssp("http://invalid.url") // to see, if cached response is used
                    .build()
                    .verifyOcspResponse(cache))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifySspUrlInvalidThrowsGemPkiExceptionOnly() {
    final OcspTransceiver builder =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp("https://no/wiremock/started")
            .build();
    assertThatThrownBy(() -> builder.verifyOcspResponse(null))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void sendOcspRequestReceiveOcspResponseGood() throws GemPkiException {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OCSPResp ocspRespRx = getOcspTransceiver().sendOcspRequest(ocspReq).orElseThrow();

    assertThat(ocspReq).isNotNull();
    assertDoesNotThrow(
        () ->
            TucPki006OcspVerifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .eeCert(VALID_X509_EE_CERT)
                .ocspResponse(ocspRespRx)
                .build()
                .verifyStatus());
  }

  @Test
  void sendOcspRequestReceiveOcspResponseGoodStatic() throws GemPkiException {

    final OCSPReq ocspReq = Objects.requireNonNull(configureOcspResponderMockForOcspRequest());

    final OCSPResp ocspRespRx = getOcspTransceiver().sendOcspRequest(ocspReq).orElseThrow();

    assertDoesNotThrow(
        () ->
            TucPki006OcspVerifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .eeCert(VALID_X509_EE_CERT)
                .ocspResponse(ocspRespRx)
                .build()
                .verifyStatus());
  }

  @Test
  void sendOcspRequestReceiveOcspResponseOptIsEmpty() {

    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);

    final OcspTransceiver transceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp("dummyUrl")
            .tolerateOcspFailure(true)
            .ocspTimeoutSeconds(10000)
            .build();

    assertDoesNotThrow(() -> transceiver.verifyOcspResponse(null, referenceDate));
  }

  @Test
  void sendOcspRequestUnreachableUrl() {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp("http://127.0.0.1:4545/unreachable")
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .build();

    assertThatThrownBy(() -> ocspTransceiver.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void sendOcspRequestUnreachableUrlTolerateOcspFailure() {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp("http://127.0.0.1:4545/unreachable")
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(true)
            .build();

    assertDoesNotThrow(() -> ocspTransceiver.sendOcspRequest(ocspReq));
  }

  /** OcspResponderMock will send OcspResponse with HttpStatus 404 */
  @Test
  void sendOcspRequestUnknownEndpoint() {

    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
    final String ssp = ocspResponderMock.getSspUrl() + "unknownEndpoint";

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp(ssp)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .build();

    assertThatThrownBy(() -> ocspTransceiver.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(OCSP_SEND_RECEIVE_FAILED);
  }

  @Test
  void nonNull() {
    final OcspTransceiver ocspTransceiver = getOcspTransceiver();
    assertThatThrownBy(() -> ocspTransceiver.sendOcspRequest(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("ocspReq is marked non-null but is null");
  }

  private OCSPReq configureOcspResponderMockForOcspRequest() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
    ocspResponderMock.configureForOcspRequest(ocspReq, VALID_X509_EE_CERT);
    return ocspReq;
  }
}
