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

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver.OCSP_SEND_RECEIVE_FAILED;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OcspTransceiverTest {

  private static OcspResponderMock ocspResponderMock;

  private static final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @BeforeAll
  public void setup() {
    ocspResponderMock = OcspResponderMock.createAndStart(LOCAL_SSP_DIR, OCSP_HOST, null);
  }

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
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
  void getOcspResponse_whenSspUrlIsInvalid_thenThrowsGemPkiException() {
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
  void sendOcspRequest_whenResponderReturnsGoodOcspResponse_thenReturnsResponse()
      throws GemPkiException {
    final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

    final OCSPResp ocspRespRx = getOcspTransceiver().sendOcspRequest(ocspReq).orElseThrow();

    assertThat(ocspReq).isNotNull();
    assertDoesNotThrow(() -> OcspVerification.verifyStatus(PRODUCT_TYPE, ocspRespRx));
  }

  @Test
  void sendOcspRequest_whenRequestIsWrappedWithRequireNonNull_thenReturnsResponse()
      throws GemPkiException {

    final OCSPReq ocspReq = Objects.requireNonNull(configureOcspResponderMockForOcspRequest());

    final OCSPResp ocspRespRx = getOcspTransceiver().sendOcspRequest(ocspReq).orElseThrow();

    assertDoesNotThrow(() -> OcspVerification.verifyStatus(PRODUCT_TYPE, ocspRespRx));
  }

  @Test
  void getOcspResponse_whenSspIsInvalidAndOcspFailureIsTolerated_thenDoesNotThrow() {

    final OcspTransceiver transceiver =
        OcspTransceiver.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .x509IssuerCert(VALID_ISSUER_CERT_SMCB)
            .ssp("dummyUrl")
            .tolerateOcspFailure(true)
            .ocspTimeoutSeconds(10000)
            .build();

    assertDoesNotThrow(() -> transceiver.getOcspResponse());
  }

  @Test
  void sendOcspRequest_whenSspIsUnreachableAndFailureIsNotTolerated_thenThrowsGemPkiException() {
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
  void sendOcspRequest_whenSspIsUnreachableAndOcspFailureIsTolerated_thenDoesNotThrow() {
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
  void sendOcspRequest_whenSspIsUnreachableAndTolerateOcspFailureIsEnabled_thenDoesNotThrow() {
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
  void sendOcspRequest_whenEndpointReturnsHttp404_thenThrowsGemPkiException() {

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
  void sendOcspRequest_whenEndpointReturnsHttp404AndOcspFailureIsTolerated_thenDoesNotThrow() {

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
  void sendOcspRequest_whenOcspRequestIsNull_thenThrowsOnNonNullParameter() {
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
  void sendOcspRequest_whenRequestEncodingFails_thenThrowsGemPkiRuntimeException()
      throws IOException {
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
  void
      sendOcspRequest_whenFutureGetIsInterruptedAndFailureIsNotTolerated_thenThrowsGemPkiException()
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
  void sendOcspRequest_whenFutureGetIsInterruptedAndFailureIsTolerated_thenDoesNotThrow()
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
  void
      sendOcspRequest_whenFutureGetThrowsExecutionExceptionAndFailureIsNotTolerated_thenThrowsGemPkiException()
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
  void sendOcspRequest_whenFutureGetThrowsExecutionExceptionAndFailureIsTolerated_thenDoesNotThrow()
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
  void sendOcspRequest_whenFutureGetTimesOut_thenThrowsGemPkiException()
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
  void sendOcspRequest_whenReadingOcspResponseBodyFails_thenThrowsGemPkiRuntimeException()
      throws IOException {
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
