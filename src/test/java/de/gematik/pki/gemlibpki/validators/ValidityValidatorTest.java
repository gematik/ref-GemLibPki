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

package de.gematik.pki.gemlibpki.validators;

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ValidityValidatorTest {

  private static final X509Certificate VALID_X509_EE_CERT =
      TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
  private static final ZonedDateTime ZONED_DATE_TIME = ZonedDateTime.parse("2020-11-20T15:00:00Z");
  private ValidityValidator tested;

  @BeforeEach
  void setUp() {
    tested = new ValidityValidator(PRODUCT_TYPE);
  }

  @Test
  void verifyConstructorNullParameter() {
    assertNonNullParameter(() -> new ValidityValidator(null), "productType");
  }

  @Test
  void verifyValidateCertificateNullParameter() {

    assertNonNullParameter(() -> tested.validateCertificate(null), "x509EeCert");
    assertNonNullParameter(() -> tested.validateCertificate(null, ZONED_DATE_TIME), "x509EeCert");
    assertNonNullParameter(() -> tested.validateCertificate(null, ZONED_DATE_TIME), "x509EeCert");

    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X509_EE_CERT, null), "referenceDate");
    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X509_EE_CERT, null), "referenceDate");
  }

  @Test
  void verifyValidityCertificateExpired() {
    final X509Certificate expiredEeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem");

    assertThatThrownBy(() -> tested.validateCertificate(expiredEeCert, ZONED_DATE_TIME))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyValidityCertificateNotYetValid() {
    final X509Certificate notYetValidEeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem");

    assertThatThrownBy(() -> tested.validateCertificate(notYetValidEeCert, ZONED_DATE_TIME))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyValidityCertificateValid() {
    assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT, ZONED_DATE_TIME));
  }
}
