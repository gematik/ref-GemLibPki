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
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ValidityValidator implements CertificateValidator {

  @NonNull private final String productType;

  /**
   * Verify validity period of parameterized end-entity certificate against a given reference date.
   * TUC_PKI_002 „Gültigkeitsprüfung des Zertifikats“
   *
   * @param referenceDate date to check against
   * @throws GemPkiException if certificate is not valid in time
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {

    final boolean isValid =
        isBetween(
            referenceDate,
            x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC),
            x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC));

    if (!isValid) {
      log.debug(
          "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitsbereichs des Zertifikates.",
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME);
    }
  }

  private boolean isBetween(
      final ZonedDateTime referenceDate,
      final ZonedDateTime startDate,
      final ZonedDateTime endDate) {
    return referenceDate.isAfter(startDate) && referenceDate.isBefore(endDate);
  }
}
