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

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ShellModelValidator implements CertificateValidator {

  @NonNull private final String productType;
  @NonNull private final X509Certificate x509IssuerCert;

  /**
   * Verify that both the end-entity certificate and the issuing CA certificate are valid at the
   * given reference date.
   *
   * @throws GemPkiException if at least one certificate is not valid at the reference date
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert, @NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {

    final ZonedDateTime issuerNotBefore =
        x509IssuerCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime issuerNotAfter =
        x509IssuerCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime eeNotBefore = x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime eeNotAfter = x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC);

    final boolean eeCertValidAtReferenceDate = isBetween(referenceDate, eeNotBefore, eeNotAfter);
    final boolean issuerCertValidAtReferenceDate =
        isBetween(referenceDate, issuerNotBefore, issuerNotAfter);

    if (!eeCertValidAtReferenceDate || !issuerCertValidAtReferenceDate) {
      log.debug(
          "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitszeitraums des"
              + " End-Entity-Zertifikats [{} - {}] oder des CA-Zertifikats [{} - {}].",
          referenceDate,
          eeNotBefore,
          eeNotAfter,
          issuerNotBefore,
          issuerNotAfter);
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
