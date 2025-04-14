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

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hc.core5.http.HttpHeaders;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

/** Class to send OCSP requests and receive OCSP responses */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class OcspTransceiver {

  public static final String OCSP_SEND_RECEIVE_FAILED = "OCSP senden/empfangen fehlgeschlagen.";
  @NonNull private final String productType;
  @NonNull private final X509Certificate x509EeCert;
  @NonNull private final X509Certificate x509IssuerCert;
  @NonNull private final String ssp;

  @Builder.Default
  private final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default private final boolean tolerateOcspFailure = false;

  public Optional<OCSPResp> getOcspResponse() throws GemPkiException {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert);
    return sendOcspRequest(ocspReq);
  }

  private void handleWithTolerateOcspFailure() throws GemPkiException {
    if (tolerateOcspFailure) {
      log.warn(ErrorCode.TW_1028_OCSP_CHECK_REVOCATION_FAILED.getErrorMessage(productType));
    } else {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }

  private void handleWithTolerateOcspFailure(final Exception e) throws GemPkiException {
    if (tolerateOcspFailure) {
      log.warn(ErrorCode.TW_1028_OCSP_CHECK_REVOCATION_FAILED.getErrorMessage(productType), e);
    } else {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR, e);
    }
  }

  Future<Pair<HttpResponse<byte[]>, Exception>> getFuture(
      final ExecutorService executor,
      final Callable<Pair<HttpResponse<byte[]>, Exception>> callableTask) {
    return executor.submit(callableTask);
  }

  OCSPResp getOcspRespForBody(final byte[] body) throws IOException {
    return new OCSPResp(body);
  }

  /**
   * Sends given OCSP request to given SSP. For use without response validation.
   *
   * @param ocspReq OCSP request to sent
   * @return received OCSP response
   */
  public Optional<OCSPResp> sendOcspRequest(@NonNull final OCSPReq ocspReq) throws GemPkiException {

    log.info("Sending OCSP Request for end entity certificate to: {}", ssp);

    final byte[] ocspReqEncoded;
    try {
      ocspReqEncoded = ocspReq.getEncoded();
    } catch (final IOException e) {
      throw new GemPkiRuntimeException(OCSP_SEND_RECEIVE_FAILED, e);
    }

    final Callable<Pair<HttpResponse<byte[]>, Exception>> callableTask =
        () -> sendOcspRequest(ssp, ocspReqEncoded);

    final ExecutorService executor = Executors.newSingleThreadExecutor();
    final Pair<HttpResponse<byte[]>, Exception> result;
    try {
      final Future<Pair<HttpResponse<byte[]>, Exception>> future =
          getFuture(executor, callableTask);
      result = future.get(ocspTimeoutSeconds, TimeUnit.SECONDS);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      handleWithTolerateOcspFailure(e);
      return Optional.empty();

    } catch (final ExecutionException e) {
      handleWithTolerateOcspFailure(e);
      return Optional.empty();

    } catch (final TimeoutException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1032_OCSP_NOT_AVAILABLE, e);

    } finally {
      executor.shutdown();
    }

    final Exception sendOcspRequestException = result.getRight();
    if (sendOcspRequestException != null) {
      handleWithTolerateOcspFailure(sendOcspRequestException);
      return Optional.empty();
    }

    final HttpResponse<byte[]> httpResponse = result.getLeft();

    if (httpResponse.getStatus() == HttpURLConnection.HTTP_OK) {
      final byte[] body = httpResponse.getBody();
      final OCSPResp ocspResp;

      try {
        ocspResp = getOcspRespForBody(body);
      } catch (final IOException e) {
        throw new GemPkiRuntimeException(OCSP_SEND_RECEIVE_FAILED, e);
      }

      return Optional.of(ocspResp);
    }

    handleWithTolerateOcspFailure();
    return Optional.empty();
  }

  private Pair<HttpResponse<byte[]>, Exception> sendOcspRequest(
      final String ssp, final byte[] ocspReqEncoded) {

    try {
      return Pair.of(
          Unirest.post(ssp)
              .header(HttpHeaders.CONTENT_TYPE, OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
              .body(ocspReqEncoded)
              .asBytes(),
          null);

    } catch (final UnirestException e) {
      return Pair.of(null, e);
    }
  }
}
