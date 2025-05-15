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

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_HBA_AUT_ECC;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_INVALID_KEY_USAGE;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_ANY;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_RSA;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeyUsageValidatorTest {

  private static final CertificateProfile CERTIFICATE_PROFILE = CERT_PROFILE_C_HCI_AUT_ECC;
  private static final X509Certificate VALID_X_509_EE_CERT =
      TestUtils.readCert("GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem");
  private KeyUsageValidator tested;

  @BeforeEach
  void setUp() {
    tested = new KeyUsageValidator(PRODUCT_TYPE);
  }

  @Test
  void verifyConstructorNullParameter() {
    assertNonNullParameter(() -> new KeyUsageValidator(null), "productType");
  }

  @Test
  void verifyValidateCertificateNullParameter() {
    assertNonNullParameter(
        () -> tested.validateCertificate(null, CERTIFICATE_PROFILE), "x509EeCert");
    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X_509_EE_CERT, null), "certificateProfile");
  }

  @Test
  void verifyKeyUsageValid() {
    assertDoesNotThrow(() -> tested.validateCertificate(VALID_X_509_EE_CERT, CERTIFICATE_PROFILE));
  }

  @Test
  void verifyKeyUsageInvalidInCertificateButNotChecked() {
    assertDoesNotThrow(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERT_PROFILE_ANY));
  }

  @Test
  void verifyKeyUsageMissingInCertificate() {
    final X509Certificate missingKeyUsages509EeCert =
        TestUtils.readCert("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-keyUsage.pem");

    assertThatThrownBy(
            () -> tested.validateCertificate(missingKeyUsages509EeCert, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyKeyUsageInvalidInCertificate() {

    assertThatThrownBy(
            () ->
                tested.validateCertificate(
                    VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNotAllKeyUsagesPresentInCert() {
    assertThatThrownBy(
            () -> tested.validateCertificate(VALID_X_509_EE_CERT, CERT_PROFILE_C_HCI_AUT_RSA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyToManyKeyUsagesPresentInCert() {
    assertThatThrownBy(
            () -> tested.validateCertificate(VALID_HBA_AUT_ECC, CERT_PROFILE_C_HCI_AUT_ECC))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }
}
