/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.ocsp.OcspTransceiver.OCSP_SEND_RECEIVE_FAILED;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class OcspTransceiverTest {

  private static List<TspService> tspServiceList;

  private static OcspResponderMock ocspResponderMock;

  private static final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @BeforeAll
  public static void start() {
    ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    tspServiceList = TestUtils.getDefaultTspServiceList();
  }

  private static OcspTransceiver getOcspTransceiver() {
    return getOcspTransceiver(ocspResponderMock.getSspUrl(), false);
  }

  private static OcspTransceiver getOcspTransceiver(
      final String ssp, final boolean tolerateOcspFailure) {
    return OcspTransceiver.builder()
        .productType(PRODUCT_TYPE)
        .x509EeCert(VALID_X509_EE_CERT_SMCB)
        .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
        .ssp(ssp)
        .ocspTimeoutSeconds(ocspTimeoutSeconds)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }

  @Test
  void verifySspUrlInvalidThrowsGemPkiExceptionOnly() {
    final OcspTransceiver builder =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp("https://no/wiremock/started")
            .build();
    assertThatThrownBy(builder::getOcspResponse)
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
                .eeCert(VALID_X509_EE_CERT_SMCB)
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
                .eeCert(VALID_X509_EE_CERT_SMCB)
                .ocspResponse(ocspRespRx)
                .build()
                .verifyStatus());
  }

  @Test
  void sendOcspRequestReceiveOcspResponseOptIsEmpty() {

    final OcspTransceiver transceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp("dummyUrl")
            .tolerateOcspFailure(true)
            .ocspTimeoutSeconds(10000)
            .build();

    assertDoesNotThrow(transceiver::getOcspResponse);
  }

  @Test
  void sendOcspRequestUnreachableUrl() {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp("http://127.0.0.1:4545/unreachable")
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .build();

    assertThatThrownBy(() -> ocspTransceiver.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void sendOcspRequestUnreachableUrlTolerate() {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp("http://127.0.0.1:4545/unreachable")
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(true)
            .build();

    assertDoesNotThrow(() -> ocspTransceiver.sendOcspRequest(ocspReq));
  }

  @Test
  void sendOcspRequestUnreachableUrlTolerateOcspFailure() {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
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
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp(ssp)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .build();

    assertThatThrownBy(() -> ocspTransceiver.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void sendOcspRequestUnknownEndpointTolerate() {

    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
    final String ssp = ocspResponderMock.getSspUrl() + "unknownEndpoint";

    final OcspTransceiver ocspTransceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp(ssp)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(true)
            .build();

    assertDoesNotThrow(() -> ocspTransceiver.sendOcspRequest(ocspReq));
  }

  @Test
  void nonNull() {
    final OcspTransceiver ocspTransceiver = getOcspTransceiver();
    assertNonNullParameter(() -> ocspTransceiver.sendOcspRequest(null), "ocspReq");
  }

  private OCSPReq configureOcspResponderMockForOcspRequest() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    ocspResponderMock.configureForOcspRequest(
        ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    return ocspReq;
  }

  @Test
  void sendOcspRespGetEncoded_IOException() throws IOException {
    final OCSPReq ocspReqReal =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPReq ocspReq = Mockito.spy(ocspReqReal);
    Mockito.when(ocspReq.getEncoded()).thenThrow(new IOException());

    final OcspTransceiver transceiver = getOcspTransceiver("", false);

    assertThatThrownBy(() -> transceiver.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(OCSP_SEND_RECEIVE_FAILED)
        .cause()
        .isInstanceOf(IOException.class);
  }

  @Test
  void sendOcspRespFutureGetBad_InterruptedException()
      throws ExecutionException, InterruptedException, TimeoutException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final Future<?> future = Mockito.spy(Future.class);
    Mockito.doThrow(InterruptedException.class)
        .when(future)
        .get(Mockito.anyLong(), Mockito.eq(TimeUnit.SECONDS));

    final OcspTransceiver transceiver = getOcspTransceiver("", false);

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doReturn(future).when(transceiverSpy).getFuture(Mockito.any(), Mockito.any());

    assertThatThrownBy(() -> transceiverSpy.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE))
        .cause()
        .isInstanceOf(InterruptedException.class);
  }

  @Test
  void sendOcspRespFutureGetBad_InterruptedException_tolerate()
      throws ExecutionException, InterruptedException, TimeoutException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final Future<?> future = Mockito.spy(Future.class);
    Mockito.doThrow(InterruptedException.class)
        .when(future)
        .get(Mockito.anyLong(), Mockito.eq(TimeUnit.SECONDS));

    final OcspTransceiver transceiver = getOcspTransceiver("", true);

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doReturn(future).when(transceiverSpy).getFuture(Mockito.any(), Mockito.any());

    assertDoesNotThrow(() -> transceiverSpy.sendOcspRequest(ocspReq));
  }

  @Test
  void sendOcspRespFutureGetBad_ExecutionException()
      throws ExecutionException, InterruptedException, TimeoutException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final Future<?> future = Mockito.spy(Future.class);
    Mockito.doThrow(ExecutionException.class)
        .when(future)
        .get(Mockito.anyLong(), Mockito.eq(TimeUnit.SECONDS));

    final OcspTransceiver transceiver = getOcspTransceiver("", false);

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doReturn(future).when(transceiverSpy).getFuture(Mockito.any(), Mockito.any());

    assertThatThrownBy(() -> transceiverSpy.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE))
        .cause()
        .isInstanceOf(ExecutionException.class);
  }

  @Test
  void sendOcspRespFutureGetBad_ExecutionException_tolerate()
      throws ExecutionException, InterruptedException, TimeoutException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final Future<?> future = Mockito.spy(Future.class);
    Mockito.doThrow(ExecutionException.class)
        .when(future)
        .get(Mockito.anyLong(), Mockito.eq(TimeUnit.SECONDS));

    final OcspTransceiver transceiver = getOcspTransceiver("", true);

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doReturn(future).when(transceiverSpy).getFuture(Mockito.any(), Mockito.any());

    assertDoesNotThrow(() -> transceiverSpy.sendOcspRequest(ocspReq));
  }

  @Test
  void sendOcspRespFutureGetBad_TimeoutException()
      throws ExecutionException, InterruptedException, TimeoutException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final Future<?> future = Mockito.spy(Future.class);
    Mockito.doThrow(TimeoutException.class)
        .when(future)
        .get(Mockito.anyLong(), Mockito.eq(TimeUnit.SECONDS));

    final OcspTransceiver transceiver = getOcspTransceiver("", false);

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doReturn(future).when(transceiverSpy).getFuture(Mockito.any(), Mockito.any());

    assertThatThrownBy(() -> transceiverSpy.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1032_OCSP_NOT_AVAILABLE.getErrorMessage(PRODUCT_TYPE))
        .cause()
        .isInstanceOf(TimeoutException.class);
  }

  @Test
  void sendOcspRespOcspForBodyBad_IOException() throws IOException {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OcspTransceiver transceiver = getOcspTransceiver();

    final OcspTransceiver transceiverSpy = Mockito.spy(transceiver);
    Mockito.doThrow(IOException.class).when(transceiverSpy).getOcspRespForBody(Mockito.any());

    assertThatThrownBy(() -> transceiverSpy.sendOcspRequest(ocspReq))
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(IOException.class);
  }
}
