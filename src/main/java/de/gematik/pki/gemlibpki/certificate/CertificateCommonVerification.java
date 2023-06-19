/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Class for common verification checks on a certificate. This class works with parameterized
 * variables (defined by builder pattern) and with given variables provided by runtime (method
 * parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class CertificateCommonVerification {

  static {
    setBouncyCastleProvider();
  }

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset tspServiceSubset;
  @NonNull private final X509Certificate x509EeCert;

  /**
   * Perform verifications of validity, signature and issue service status
   *
   * @throws GemPkiException thrown if cert is not valid according to time, signature or issuer
   *     service status
   */
  public void verifyAll() throws GemPkiException {
    verifyValidity();
    verifySignature(tspServiceSubset.getX509IssuerCert());
    verifyIssuerServiceStatus();
  }

  /**
   * Verify validity period of parameterized end-entity certificate against current date.
   *
   * @throws GemPkiException thrown if cert is not valid in time
   */
  public void verifyValidity() throws GemPkiException {
    verifyValidity(ZonedDateTime.now());
  }

  /**
   * Verify validity period of parameterized end-entity certificate against a given reference date.
   * TUC_PKI_002 „Gültigkeitsprüfung des Zertifikats“
   *
   * @param referenceDate date to check against
   * @throws GemPkiException if certificate is not valid in time
   */
  public void verifyValidity(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {
    final boolean isValidBeforeReferenceDate =
        x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC).isAfter(referenceDate);
    final boolean isValidAfterReferenceDate =
        x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC).isBefore(referenceDate);

    if (isValidBeforeReferenceDate || isValidAfterReferenceDate) {
      log.debug(
          "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitsbereichs des Zertifikates.",
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME);
    }
  }

  /**
   * Verify signature of parameterized end-entity certificate against given issuer certificate.
   * Issuer certificate (CA) is determined from TSL file.
   *
   * @param x509IssuerCert issuer certificate
   * @throws GemPkiException if certificate is mathematically invalid
   */
  public void verifySignature(@NonNull final X509Certificate x509IssuerCert)
      throws GemPkiException {

    try {
      x509EeCert.verify(x509IssuerCert.getPublicKey());
      log.debug("Signaturprüfung von {} erfolgreich", x509EeCert.getSubjectX500Principal());
    } catch (final GeneralSecurityException verifyFailed) {
      throw new GemPkiException(
          productType, ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH, verifyFailed);
    }
  }

  // ####################  Start issuer checks ######################

  /**
   * Verify issuer service status from tsl file. The status determines if an end-entity certificate
   * was issued after the CA (Issuer) was revoked.
   *
   * @throws GemPkiException if certificate has been revoked
   */
  public void verifyIssuerServiceStatus() throws GemPkiException {
    if (!tspServiceSubset.getServiceStatus().equals(TslConstants.SVCSTATUS_REVOKED)) {
      return;
    }

    final ZonedDateTime statusStartingTime = tspServiceSubset.getStatusStartingTime();
    final ZonedDateTime notBefore = x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);

    if (statusStartingTime.isBefore(notBefore)) {
      throw new GemPkiException(productType, ErrorCode.SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL);
    }
  }
  // ####################  End issuer checks ########################
}
