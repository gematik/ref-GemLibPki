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

import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.verifyHashAlgoSupported;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspUtils.getBasicOcspResp;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspUtils.getFirstSingleResp;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public final class OcspVerification {

  /**
   * Verify the status of the parameterized ocsp response
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @param referenceDate reference date for the revocation time to check against
   * @throws GemPkiException thrown if response status is not SUCCESSFUL (0)
   */
  public static void verifyStatus(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    if (ocspResponse.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
      throw new GemPkiException(productType, ErrorCode.TE_1058_OCSP_STATUS_ERROR);
    }

    final CertificateStatus certificateStatus = getFirstSingleResp(ocspResponse).getCertStatus();

    if (CertificateStatus.GOOD == certificateStatus) {
      return;
    }

    if (certificateStatus instanceof final RevokedStatus revokedStatus) {

      final ZonedDateTime revocationTime =
          ZonedDateTime.ofInstant(revokedStatus.getRevocationTime().toInstant(), ZoneOffset.UTC);

      if (revocationTime.isAfter(referenceDate)) {
        return;
      }

      throw new GemPkiException(productType, ErrorCode.SW_1047_CERT_REVOKED);

    } else {
      // the only remaining case: certificateStatus instanceof UnknownStatus
      throw new GemPkiException(productType, ErrorCode.TW_1044_CERT_UNKNOWN);
    }
  }

  /**
   * Verify the status of the parameterized ocsp response
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @throws GemPkiException thrown if response status is not SUCCESSFUL (0)
   */
  public static void verifyStatus(
      @NonNull final String productType, @NonNull final OCSPResp ocspResponse)
      throws GemPkiException {
    verifyStatus(productType, ocspResponse, GemLibPkiUtils.now());
  }

  public static void verifyNonce(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      final Extension expectedNonce)
      throws GemPkiException {
    if (expectedNonce == null) {
      return;
    }

    final Extension responseNonce =
        getBasicOcspResp(ocspResponse).getExtension(expectedNonce.getExtnId());
    if (!expectedNonce.equals(responseNonce)) {
      throw new GemPkiException(productType, ErrorCode.SE_1051_OCSP_NONCE_MISMATCH);
    }
  }

  /**
   * Verify that thisUpdate of the OCSP response is within its tolerance of {@link
   * OcspConstants#OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS} in the future. Throws an
   * exception if not.
   *
   * <p>thisUpdate: The time at which the status being indicated is known to be correct
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @param referenceDate a reference date to check thisUpdate against
   * @throws GemPkiException thrown if ocsp thisUpdate is in future out of tolerance
   */
  public static void verifyThisUpdate(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    final SingleResp singleResp = getFirstSingleResp(ocspResponse);

    final Instant thisUpdateInstant = singleResp.getThisUpdate().toInstant();
    final ZonedDateTime thisUpdate = ZonedDateTime.ofInstant(thisUpdateInstant, ZoneOffset.UTC);

    verifyToleranceForFuture(
        productType,
        thisUpdate,
        referenceDate,
        OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS,
        "thisUpdate");
  }

  /**
   * Verify that producedAt of the OCSP response is within its tolerance in past and future. Throws
   * an exception if not.
   *
   * <p>producedAt: The time at which the OCSP responder signed this response.
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @param referenceDate a reference date to check producedAt against
   * @param pastToleranceMilliSeconds allowed past tolerance
   * @param futureToleranceMilliSeconds allowed future tolerance
   * @throws GemPkiException thrown if ocsp producedAt is out of tolerance
   */
  public static void verifyProducedAt(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate,
      final int pastToleranceMilliSeconds,
      final int futureToleranceMilliSeconds)
      throws GemPkiException {
    final Instant producedAtInstant = getBasicOcspResp(ocspResponse).getProducedAt().toInstant();
    final ZonedDateTime producedAt = ZonedDateTime.ofInstant(producedAtInstant, ZoneOffset.UTC);

    verifyToleranceForPast(
        productType, producedAt, referenceDate, pastToleranceMilliSeconds, "producedAt");
    verifyToleranceForFuture(
        productType, producedAt, referenceDate, futureToleranceMilliSeconds, "producedAt");
  }

  public static void verifyProvidedOcspResponseTimePlausibility(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate,
      final int futureToleranceMilliSeconds)
      throws GemPkiException {
    final SingleResp singleResp = getFirstSingleResp(ocspResponse);
    final ZonedDateTime thisUpdate =
        ZonedDateTime.ofInstant(singleResp.getThisUpdate().toInstant(), ZoneOffset.UTC);
    final ZonedDateTime producedAt =
        ZonedDateTime.ofInstant(
            getBasicOcspResp(ocspResponse).getProducedAt().toInstant(), ZoneOffset.UTC);

    verifyToleranceForFuture(
        productType,
        thisUpdate,
        referenceDate,
        OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS,
        "thisUpdate");

    if (producedAt.isBefore(thisUpdate)) {
      log.error(
          "The producedAt value {} of the OCSP response is before thisUpdate {}.",
          producedAt,
          thisUpdate);
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }

    verifyToleranceForFuture(
        productType, producedAt, referenceDate, futureToleranceMilliSeconds, "producedAt");
  }

  public static void verifyProvidedOcspResponse(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate,
      @NonNull final ZonedDateTime plausibilityReferenceDate,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final int futureToleranceMilliSeconds)
      throws GemPkiException {
    verifyStatus(productType, ocspResponse, referenceDate);
    verifyOcspResponseCertId(productType, ocspResponse, eeCert, issuerCert);
    verifyProvidedOcspResponseTimePlausibility(
        productType, ocspResponse, plausibilityReferenceDate, futureToleranceMilliSeconds);
  }

  public static void verifyOcspResponse(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate,
      @NonNull final ZonedDateTime plausibilityReferenceDate,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final int pastToleranceMilliSeconds,
      final int futureToleranceMilliSeconds)
      throws GemPkiException {
    verifyStatus(productType, ocspResponse, referenceDate);
    verifyOcspResponseAfterStatus(
        productType,
        ocspResponse,
        referenceDate,
        plausibilityReferenceDate,
        eeCert,
        issuerCert,
        pastToleranceMilliSeconds,
        futureToleranceMilliSeconds);
  }

  public static void verifyOcspResponseAfterStatus(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate,
      @NonNull final ZonedDateTime plausibilityReferenceDate,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final int pastToleranceMilliSeconds,
      final int futureToleranceMilliSeconds)
      throws GemPkiException {
    verifyThisUpdate(productType, ocspResponse, referenceDate);
    verifyProducedAt(
        productType,
        ocspResponse,
        referenceDate,
        pastToleranceMilliSeconds,
        futureToleranceMilliSeconds);
    verifyNextUpdate(productType, ocspResponse, referenceDate);
    verifyOcspResponseCertId(productType, ocspResponse, eeCert, issuerCert);
    verifyProvidedOcspResponseTimePlausibility(
        productType, ocspResponse, plausibilityReferenceDate, futureToleranceMilliSeconds);
  }

  /**
   * Verify that producedAt of the OCSP response is within the default tolerances in past and
   * future. Throws an exception if not.
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @param referenceDate a reference date to check producedAt against
   * @throws GemPkiException thrown if ocsp producedAt is out of tolerance
   */
  public static void verifyProducedAt(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    verifyProducedAt(
        productType,
        ocspResponse,
        referenceDate,
        OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
        OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS);
  }

  /**
   * Verify that nextUpdate of the OCSP response is within its tolerance of {@link
   * OcspConstants#OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS} in the past. Throws an exception
   * if not. The verification is not performed, if nextUpdate is not available.
   *
   * <p>nextUpdate: The time at or before which newer information will be available about the status
   * of the certificate
   *
   * @param productType product type for error creation
   * @param ocspResponse ocsp response to validate
   * @param referenceDate a reference date to check nextUpdate against
   * @throws GemPkiException thrown if ocsp nextUpdate is in past out of tolerance
   */
  public static void verifyNextUpdate(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    final SingleResp singleResp = getFirstSingleResp(ocspResponse);

    if (singleResp.getNextUpdate() == null) {
      log.info("nextUpdate is not set: its verification is not performed");
      return;
    }

    final Instant nextUpdateInstant = singleResp.getNextUpdate().toInstant();
    final ZonedDateTime nextUpdate = ZonedDateTime.ofInstant(nextUpdateInstant, ZoneOffset.UTC);

    verifyToleranceForPast(
        productType,
        nextUpdate,
        referenceDate,
        OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS,
        "nextUpdate");
  }

  /**
   * Verifies the OCSP cert id of the parameterized OCSP response against the corresponding
   * certificate and issuer certificate.
   *
   * @throws GemPkiException thrown if the cert ids does not match
   */
  public static void verifyOcspResponseCertId(
      @NonNull final String productType,
      @NonNull final OCSPResp ocspResponse,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert)
      throws GemPkiException {

    final CertificateID respCertId = getFirstSingleResp(ocspResponse).getCertID();
    final AlgorithmIdentifier algorithmIdentifier = respCertId.toASN1Primitive().getHashAlgorithm();

    final CertificateID computedCertId =
        OcspRequestGenerator.createCertificateId(
            eeCert.getSerialNumber(), issuerCert, algorithmIdentifier);

    try {
      verifyHashAlgoSupported(algorithmIdentifier.getAlgorithm());
    } catch (final GemPkiRuntimeException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }

    if (!respCertId.equals(computedCertId)) {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }

  private static void verifyToleranceForFuture(
      final String productType,
      final ZonedDateTime dateToVerify,
      final ZonedDateTime referenceDate,
      final int toleranceMilliSeconds,
      final String dateName)
      throws GemPkiException {

    final ZonedDateTime futureTolerance =
        referenceDate.plus(toleranceMilliSeconds, ChronoUnit.MILLIS);

    if (dateToVerify.isAfter(futureTolerance)) {

      log.error(
          "The interval for {} of the OCSP response {} is outside of the allowed {} milliseconds in"
              + " the future {}.",
          dateName,
          dateToVerify,
          toleranceMilliSeconds,
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }

  private static void verifyToleranceForPast(
      final String productType,
      final ZonedDateTime dateToVerify,
      final ZonedDateTime referenceDate,
      final int toleranceMilliSeconds,
      final String dateName)
      throws GemPkiException {

    final ZonedDateTime pastTolerance =
        referenceDate.minus(toleranceMilliSeconds, ChronoUnit.MILLIS);
    log.info("toleranceMilliSeconds: {}", toleranceMilliSeconds);
    log.info("pastTolerance: {}", pastTolerance);
    if (dateToVerify.isBefore(pastTolerance)) {
      log.error(
          "The interval for {} of the OCSP response {} is outside of the allowed {} milliseconds in"
              + " the past {}.",
          dateName,
          dateToVerify,
          toleranceMilliSeconds,
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }
}
