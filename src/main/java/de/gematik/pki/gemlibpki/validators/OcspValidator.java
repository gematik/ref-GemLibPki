/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.gemlibpki.validators;

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.ocsp.TucPki006OcspVerifier;
import de.gematik.pki.gemlibpki.tsl.TspService;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public final class OcspValidator implements CertificateValidator {

  @NonNull private final String productType;
  @NonNull private final List<TspService> tspServiceList;

  private final boolean withOcspCheck;
  private final OCSPResp ocspResponse;
  private final OcspRespCache ocspRespCache;
  private final int ocspTimeoutSeconds;
  private final OcspTransceiver ocspTransceiver;
  @Builder.Default private final boolean tolerateOcspFailure = false;

  @Builder.Default
  private int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  @Builder.Default
  private int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  /**
   * Verify signature of parameterized end-entity certificate against given issuer certificate.
   * Issuer certificate (CA) is determined from TSL file.
   *
   * @throws GemPkiException if certificate is mathematically invalid
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {

    if (!withOcspCheck) {
      log.warn(ErrorCode.SW_1039_NO_OCSP_CHECK.getErrorMessage(productType));
      return;
    }
    verifyToleranceSettings();

    // use parameterized OCSP response if available
    if (ocspResponse != null) {
      try {
        createVerifier(x509EeCert, ocspResponse).performTucPki006Checks(referenceDate);
        return;

      } catch (final GemPkiException e) {
        log.warn(ErrorCode.TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID.getErrorMessage(productType));
      }
    }

    // use cached OCSP response if available
    if (ocspRespCache != null) {
      final Optional<OCSPResp> ocspRespCachedOpt =
          ocspRespCache.getResponse(x509EeCert.getSerialNumber());

      if (ocspRespCachedOpt.isPresent()) {
        log.debug("Ocsp resp from cache: verification is not performed");
        return;
      }
    }

    // send OCSP request if no cached response is available
    final Optional<OCSPResp> ocspRespOpt = ocspTransceiver.getOcspResponse();
    if (ocspRespOpt.isEmpty()) {
      // no OCSP response available but that was tolerated (otherwise exception would have been
      // thrown)
      log.debug("No Ocsp resp received, but tolerated.");
      return;
    }

    createVerifier(x509EeCert, ocspRespOpt.get()).performTucPki006Checks(referenceDate);

    if (ocspRespCache != null) {
      ocspRespCache.saveResponse(x509EeCert.getSerialNumber(), ocspRespOpt.get());
      log.debug("Ocsp response from server saved to cache.");
    }
  }

  private void verifyToleranceSettings() {
    if (ocspTimeToleranceProducedAtPastMilliseconds <= 0) {
      throw new GemPkiRuntimeException(
          "ocspTimeToleranceProducedAtPastMilliseconds must be greater than 0");
    }
  }

  private TucPki006OcspVerifier createVerifier(
      final X509Certificate x509EeCert, final OCSPResp ocspResponse) {
    return TucPki006OcspVerifier.builder()
        .productType(productType)
        .tspServiceList(tspServiceList)
        .eeCert(x509EeCert)
        .ocspResponse(ocspResponse)
        .ocspTimeToleranceProducedAtFutureMilliseconds(
            ocspTimeToleranceProducedAtFutureMilliseconds)
        .ocspTimeToleranceProducedAtPastMilliseconds(ocspTimeToleranceProducedAtPastMilliseconds)
        .build();
  }
}
