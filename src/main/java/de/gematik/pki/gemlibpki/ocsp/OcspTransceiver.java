/*
 * Copyright 2023 gematik GmbH
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

package de.gematik.pki.gemlibpki.ocsp;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TspService;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
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
import org.apache.http.HttpHeaders;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

/** Class to send OCSP requests and receive OCSP responses */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class OcspTransceiver {

  public static final String OCSP_SEND_RECEIVE_FAILED = "OCSP senden/empfangen fehlgeschlagen.";
  @NonNull private final String productType;
  @NonNull private final List<TspService> tspServiceList;
  @NonNull private final X509Certificate x509EeCert;
  @NonNull private final X509Certificate x509IssuerCert;
  @NonNull private final String ssp;

  @Builder.Default
  private final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default private final boolean tolerateOcspFailure = false;

  public TucPki006OcspVerifier getTucPki006Verifier(final OCSPResp ocspResp) {

    return TucPki006OcspVerifier.builder()
        .productType(productType)
        .tspServiceList(tspServiceList)
        .eeCert(x509EeCert)
        .ocspResponse(ocspResp)
        .build();
  }

  /**
   * Verifies OCSP status of end-entity certificate. Sends OCSP request if OCSP response is not
   * cached.
   *
   * @param ocspRespCache Cache for OCSP Responses
   * @param referenceDate date at which the ocsp response shall be valid at
   * @throws GemPkiException during ocsp checks
   */
  public void verifyOcspResponse(
      final OcspRespCache ocspRespCache, final ZonedDateTime referenceDate) throws GemPkiException {

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert);

    if (ocspRespCache == null) {
      log.debug("Send Ocsp req because no cache.");
      final Optional<OCSPResp> ocspRespOpt = sendOcspRequest(ocspReq);
      if (ocspRespOpt.isEmpty()) {
        return;
      }
      log.debug("Ocsp resp from server, because no cache.");
      getTucPki006Verifier(ocspRespOpt.get()).performTucPki006Checks(referenceDate);
      return;
    }

    final Optional<OCSPResp> ocspRespCachedOpt =
        ocspRespCache.getResponse(x509EeCert.getSerialNumber());

    if (ocspRespCachedOpt.isPresent()) {
      log.debug("Ocsp resp from cache: verification is not performed");
      return;
    }

    log.debug("Send Ocsp req, because not in cache.");
    final Optional<OCSPResp> ocspRespOpt = sendOcspRequest(ocspReq);

    if (ocspRespOpt.isEmpty()) {
      log.debug("No Ocsp resp received.");
      return;
    }

    getTucPki006Verifier(ocspRespOpt.get()).performTucPki006Checks(referenceDate);

    ocspRespCache.saveResponse(x509EeCert.getSerialNumber(), ocspRespOpt.get());
    log.debug("Ocsp resp from server saved to cache.");
  }

  /**
   * Verifies OCSP status of end-entity certificate for the current date time. Sends OCSP request if
   * OCSP response is not cached.
   *
   * @param ocspRespCache Cache for OCSP Responses
   * @throws GemPkiException during ocsp checks
   */
  public void verifyOcspResponse(final OcspRespCache ocspRespCache) throws GemPkiException {
    verifyOcspResponse(ocspRespCache, ZonedDateTime.now(ZoneOffset.UTC));
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
