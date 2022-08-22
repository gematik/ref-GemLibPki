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

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TspService;
import java.io.IOException;
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
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
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
@RequiredArgsConstructor
@Builder
public class OcspTransceiver {

  public static final String OCSP_SEND_RECEIVE_FAILED = "OCSP senden/empfangen fehlgeschlagen.";
  @NonNull private final String productType;
  @NonNull protected final List<TspService> tspServiceList;
  @NonNull private final X509Certificate x509EeCert;
  @NonNull private final X509Certificate x509IssuerCert;
  @NonNull private final String ssp;

  @Builder.Default
  private final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default private final boolean tolerateOcspFailure = false;

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

    final OCSPResp ocspResp;
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert);

    if (ocspRespCache != null) {
      final Optional<OCSPResp> ocspRespCachedOpt =
          ocspRespCache.getResponse(x509EeCert.getSerialNumber());
      if (ocspRespCachedOpt.isEmpty()) {
        final Optional<OCSPResp> ocspRespOpt = sendOcspRequest(ocspReq);
        if (ocspRespOpt.isEmpty()) {
          return;
        }
        ocspResp = ocspRespCache.saveResponse(x509EeCert.getSerialNumber(), ocspRespOpt.get());
      } else {
        ocspResp = ocspRespCachedOpt.get();
      }

    } else {
      final Optional<OCSPResp> ocspRespOpt = sendOcspRequest(ocspReq);
      if (ocspRespOpt.isEmpty()) {
        return;
      }
      ocspResp = ocspRespOpt.get();
    }

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(productType)
            .tspServiceList(tspServiceList)
            .eeCert(x509EeCert)
            .ocspResponse(ocspResp)
            .build();

    verifier.performOcspChecks(ocspReq, referenceDate);
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

  private void handleWithTolerateOcspFailure(final Exception e) throws GemPkiException {
    if (tolerateOcspFailure) {
      log.warn(ErrorCode.TW_1028_OCSP_CHECK_REVOCATION_FAILED.getErrorMessage(productType), e);
    } else {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR, e);
    }
  }

  /**
   * Sends given OCSP request to given SSP. For use without response validation.
   *
   * @param ocspReq OCSP request to sent
   * @return received OCSP response
   */
  public Optional<OCSPResp> sendOcspRequest(@NonNull final OCSPReq ocspReq) throws GemPkiException {

    log.info(
        "Send OCSP Request for certificate serial number: {} to: {}",
        ocspReq.getRequestList()[0].getCertID().getSerialNumber(),
        ssp);

    final ExecutorService executor = Executors.newSingleThreadExecutor();
    final HttpResponse<byte[]> httpResponse;

    final byte[] ocspReqEncoded;
    try {
      ocspReqEncoded = ocspReq.getEncoded();
    } catch (final IOException e) {
      throw new GemPkiRuntimeException(OCSP_SEND_RECEIVE_FAILED, e);
    }

    try {
      final Callable<Pair<HttpResponse<byte[]>, Exception>> callableTask =
          () -> sendOcspRequest(ssp, ocspReqEncoded);
      final Future<Pair<HttpResponse<byte[]>, Exception>> future = executor.submit(callableTask);
      final Pair<HttpResponse<byte[]>, Exception> result =
          future.get(ocspTimeoutSeconds, TimeUnit.SECONDS);

      final Exception sendOcspRequestException = result.getRight();
      if (sendOcspRequestException != null) {
        handleWithTolerateOcspFailure(sendOcspRequestException);
        return Optional.empty();
      }

      httpResponse = result.getLeft();

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

    try {
      log.info("HttpStatus der OcspResponse: {}", httpResponse.getStatus());
      return Optional.of(new OCSPResp(httpResponse.getBody()));
    } catch (final IOException e) {
      throw new GemPkiRuntimeException(OCSP_SEND_RECEIVE_FAILED, e);
    }
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
