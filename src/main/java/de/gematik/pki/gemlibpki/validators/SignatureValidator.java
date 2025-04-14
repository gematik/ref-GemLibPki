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

package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class SignatureValidator implements CertificateValidator {

  @NonNull private final String productType;
  @NonNull private final X509Certificate x509IssuerCert;

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

    try {
      x509EeCert.verify(x509IssuerCert.getPublicKey());
      log.debug("Signature verification for end entity certificate successful.");
    } catch (final GeneralSecurityException verifyFailed) {
      throw new GemPkiException(
          productType, ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH, verifyFailed);
    }
  }
}
