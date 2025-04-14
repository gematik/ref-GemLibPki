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

import static de.gematik.pki.gemlibpki.TestConstants.MISSING_EXT_KEY_USAGE_EE_CERT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_HBA_AUT_ECC;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_ANY;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HP_AUT_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class ExtendedKeyUsageValidatorTest {

  private static final CertificateProfile CERTIFICATE_PROFILE = CERT_PROFILE_C_HCI_AUT_ECC;

  private ExtendedKeyUsageValidator tested;

  @BeforeEach
  void setUp() {
    tested = new ExtendedKeyUsageValidator(PRODUCT_TYPE);
  }

  @Test
  void verifyConstructorNullParameter() {
    assertNonNullParameter(() -> new ExtendedKeyUsageValidator(null), "productType");
  }

  @Test
  void verifyValidateCertificateNullParameter() {
    assertNonNullParameter(
        () -> tested.validateCertificate(null, CERTIFICATE_PROFILE), "x509EeCert");
    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null), "certificateProfile");
  }

  @Test
  void verifyExtendedKeyUsageMissingInCertificateAndNotExpected() {
    assertDoesNotThrow(
        () -> tested.validateCertificate(MISSING_EXT_KEY_USAGE_EE_CERT, CERT_PROFILE_ANY));
  }

  @Test
  void verifyExtendedKeyUsageNotChecked() {

    assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERT_PROFILE_ANY));
  }

  @Test
  void verifyExtendedKeyUsageValid() {
    assertDoesNotThrow(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERTIFICATE_PROFILE));
  }

  @Test
  void verifyNotAllExtendedKeyUsagesPresentInCert() {

    assertThatThrownBy(
            () -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERT_PROFILE_C_HP_AUT_ECC))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyToManyExtendedKeyUsagesPresentInCert() {
    assertThatThrownBy(
            () -> tested.validateCertificate(VALID_HBA_AUT_ECC, CERT_PROFILE_C_HCI_AUT_ECC))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyExtendedKeyUsageMissingInCertificate() {
    assertThatThrownBy(
            () -> tested.validateCertificate(MISSING_EXT_KEY_USAGE_EE_CERT, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyExtendedKeyUsageInvalidInCertificate() {
    final X509Certificate invalidExtendedKeyUsageEeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");

    assertThatThrownBy(
            () -> tested.validateCertificate(invalidExtendedKeyUsageEeCert, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyExtendedKeyUsageCertificateParsingException() throws CertificateParsingException {

    final X509Certificate cert = Mockito.spy(VALID_X509_EE_CERT_SMCB);
    Mockito.when(cert.getExtendedKeyUsage()).thenThrow(new CertificateParsingException());

    assertThatThrownBy(() -> tested.validateCertificate(cert, CERTIFICATE_PROFILE))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(
            "Fehler beim Lesen der ExtendedKeyUsage des Zertifikats: CN=Zahnarztpraxis Dr."
                + " med.Gunther KZV"
                + " TEST-ONLY,2.5.4.5=#131731372e3830323736383833313139313130303033333237,O=2-2.30.1.16.TestOnly"
                + " NOT-VALID,C=DE");
  }
}
