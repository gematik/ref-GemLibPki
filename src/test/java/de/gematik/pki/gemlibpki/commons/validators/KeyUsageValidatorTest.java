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
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_INVALID_KEY_USAGE;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_ANY;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_RSA;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeyUsageValidatorTest {

  private static final CertificateProfile CERTIFICATE_PROFILE = CERT_PROFILE_C_HCI_AUT_ECC;
  private static final X509Certificate VALID_X_509_EE_CERT =
      TestUtils.readCertNonQes("GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem");
  private KeyUsageValidator tested;

  @BeforeEach
  void setUp() {
    tested = new KeyUsageValidator(PRODUCT_TYPE);
  }

  @Test
  void keyUsageValidator_whenProductTypeIsNull_thenThrowsNullPointerException() {
    assertNonNullParameter(() -> new KeyUsageValidator(null), "productType");
  }

  @Test
  void
      validateCertificate_whenX509EeCertOrCertificateProfileIsNull_thenThrowsNullPointerException() {
    assertNonNullParameter(
        () -> tested.validateCertificate(null, CERTIFICATE_PROFILE), "x509EeCert");
    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X_509_EE_CERT, null), "certificateProfile");
  }

  @Test
  void validateCertificate_whenCertificateContainsRequiredKeyUsage_thenDoesNotThrow() {
    assertDoesNotThrow(() -> tested.validateCertificate(VALID_X_509_EE_CERT, CERTIFICATE_PROFILE));
  }

  @Test
  void validateCertificate_whenCertificateProfileDoesNotCheckKeyUsage_thenDoesNotThrow() {
    assertDoesNotThrow(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERT_PROFILE_ANY));
  }

  @Test
  void validateCertificate_whenCertificateIsMissingKeyUsageExtension_thenThrowsGemPkiException() {
    final X509Certificate missingKeyUsages509EeCert =
        TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-keyUsage.pem");

    assertThatThrownBy(
            () -> tested.validateCertificate(missingKeyUsages509EeCert, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validateCertificate_whenCertificateContainsWrongKeyUsage_thenThrowsGemPkiException() {

    assertThatThrownBy(
            () ->
                tested.validateCertificate(
                    VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      validateCertificate_whenCertificateDoesNotContainAllRequiredKeyUsages_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () -> tested.validateCertificate(VALID_X_509_EE_CERT, CERT_PROFILE_C_HCI_AUT_RSA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }
}
