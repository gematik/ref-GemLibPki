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

import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.ocsp.TucPki030OcspVerifier;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPResp;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class TucPki030OcspValidator {

  @NonNull private final String productType;
  @NonNull protected final List<TspService> tspServiceListBNetzAVl;

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

  public void validateCertificate(
      @NonNull final java.security.cert.X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final java.time.ZonedDateTime referenceDate)
      throws GemPkiException {
    validateCertificate(x509EeCert, x509IssuerCert, referenceDate, null);
  }

  public void validateCertificate(
      @NonNull final java.security.cert.X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final java.time.ZonedDateTime referenceDate,
      final Extension nonce)
      throws GemPkiException {
    if (!withOcspCheck) {
      log.warn(ErrorCode.SW_1039_NO_OCSP_CHECK.getErrorMessage(productType));
      return;
    }
    verifyToleranceSettings();

    // use parameterized OCSP response if available
    if (ocspResponse != null) {
      try {
        createOcspVerifier(x509EeCert, x509IssuerCert, ocspResponse, nonce)
            .performChecksForProvidedOcspResponse(referenceDate);
        return;

      } catch (final GemPkiException e) {
        log.warn(ErrorCode.TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID.getErrorMessage(productType));
      }
    }

    if (ocspTransceiver == null) {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }

    final Optional<OCSPResp> ocspRespOpt = ocspTransceiver.getOcspResponse(nonce);
    if (ocspRespOpt.isEmpty()) {
      // no OCSP response available, but that was obviously tolerated (otherwise exception would
      // have been thrown)
      log.debug("No Ocsp resp received, but tolerated.");
      return;
    }

    createOcspVerifier(x509EeCert, x509IssuerCert, ocspRespOpt.get(), nonce)
        .performOcspChecks(referenceDate);
  }

  private void verifyToleranceSettings() {
    if (ocspTimeToleranceProducedAtPastMilliseconds <= 0) {
      throw new GemPkiRuntimeException(
          "ocspTimeToleranceProducedAtPastMilliseconds must be greater than 0");
    }
  }

  private TucPki030OcspVerifier createOcspVerifier(
      @NonNull final java.security.cert.X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final OCSPResp ocspResp,
      final Extension nonce) {
    return TucPki030OcspVerifier.builder()
        .productType(productType)
        .tspServiceListBNetzAVl(tspServiceListBNetzAVl)
        .eeCert(x509EeCert)
        .eeCertIssuerCert(x509IssuerCert)
        .ocspResponse(ocspResp)
        .nonce(nonce)
        .ocspTimeToleranceProducedAtFutureMilliseconds(
            ocspTimeToleranceProducedAtFutureMilliseconds)
        .ocspTimeToleranceProducedAtPastMilliseconds(ocspTimeToleranceProducedAtPastMilliseconds)
        .build();
  }
}
