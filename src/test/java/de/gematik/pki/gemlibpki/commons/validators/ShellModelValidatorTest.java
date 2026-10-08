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

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class ShellModelValidatorTest {

  private static final ZonedDateTime REFERENCE_DATE = ZonedDateTime.parse("2025-03-20T15:00:00Z");
  private static final ZonedDateTime ISSUER_NOT_BEFORE =
      ZonedDateTime.of(2025, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
  private static final ZonedDateTime ISSUER_NOT_AFTER =
      ZonedDateTime.of(2025, 12, 31, 23, 59, 59, 0, ZoneOffset.UTC);

  private ShellModelValidator shellModelValidator;

  @BeforeEach
  void setUp() {
    shellModelValidator =
        new ShellModelValidator(PRODUCT_TYPE, mockCertificate(ISSUER_NOT_BEFORE, ISSUER_NOT_AFTER));
  }

  @Test
  void
      shellModelValidator_whenProductTypeOrIssuerCertificateIsNull_thenThrowsNullPointerException() {
    final X509Certificate x509IssuerCert = Mockito.mock(X509Certificate.class);

    assertNonNullParameter(() -> new ShellModelValidator(null, x509IssuerCert), "productType");
    assertNonNullParameter(() -> new ShellModelValidator(PRODUCT_TYPE, null), "x509IssuerCert");
  }

  @Test
  void validateCertificate_whenCertificateOrReferenceDateIsNull_thenThrowsNullPointerException() {
    assertNonNullParameter(() -> shellModelValidator.validateCertificate(null), "x509EeCert");
    assertNonNullParameter(
        () -> shellModelValidator.validateCertificate(null, REFERENCE_DATE), "x509EeCert");
    assertNonNullParameter(
        () ->
            shellModelValidator.validateCertificate(
                mockCertificate(ISSUER_NOT_BEFORE, ISSUER_NOT_AFTER), null),
        "referenceDate");
  }

  @Test
  void validateCertificate_whenEeCertValidityIsWithinIssuerValidity_thenDoesNotThrow() {
    final X509Certificate x509EeCert =
        mockCertificate(ISSUER_NOT_BEFORE.plusDays(1), ISSUER_NOT_AFTER.minusDays(1));

    assertDoesNotThrow(() -> shellModelValidator.validateCertificate(x509EeCert, REFERENCE_DATE));
  }

  @Test
  void validateCertificate_whenEeCertStartsBeforeIssuer_thenThrowsGemPkiException() {
    final X509Certificate x509EeCert =
        mockCertificate(ISSUER_NOT_BEFORE.minusSeconds(1), ISSUER_NOT_AFTER.minusDays(1));

    assertThatThrownBy(() -> shellModelValidator.validateCertificate(x509EeCert, REFERENCE_DATE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validateCertificate_whenEeCertEndsAfterIssuer_thenThrowsGemPkiException() {
    final X509Certificate x509EeCert =
        mockCertificate(ISSUER_NOT_BEFORE.plusDays(1), ISSUER_NOT_AFTER.plusSeconds(1));

    assertThatThrownBy(() -> shellModelValidator.validateCertificate(x509EeCert, REFERENCE_DATE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  private X509Certificate mockCertificate(
      final ZonedDateTime notBefore, final ZonedDateTime notAfter) {
    final X509Certificate certificate = Mockito.mock(X509Certificate.class);
    Mockito.when(certificate.getNotBefore()).thenReturn(Date.from(notBefore.toInstant()));
    Mockito.when(certificate.getNotAfter()).thenReturn(Date.from(notAfter.toInstant()));
    return certificate;
  }
}
