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
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
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
import org.mockito.Mockito;

class SignatureValidatorTest {

  private SignatureValidator tested;

  @BeforeEach
  void setUp() {
    tested = new SignatureValidator(PRODUCT_TYPE, VALID_ISSUER_CERT_SMCB);
  }

  @Test
  void verifyConstructorNullParameter() {
    assertNonNullParameter(
        () -> new SignatureValidator(null, VALID_ISSUER_CERT_SMCB), "productType");
    assertNonNullParameter(() -> new SignatureValidator(PRODUCT_TYPE, null), "x509IssuerCert");
  }

  @Test
  void verifyValidateCertificateNullParameter() {
    final ZonedDateTime zonedDateTime = Mockito.mock(ZonedDateTime.class);

    assertNonNullParameter(() -> tested.validateCertificate(null), "x509EeCert");
    assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime), "x509EeCert");
    assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime), "x509EeCert");

    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null), "referenceDate");
    assertNonNullParameter(
        () -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null), "referenceDate");
  }

  @Test
  void verifySignatureValid() {
    assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void verifySignatureNotValid() {
    final X509Certificate invalidX509EeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem");

    assertThatThrownBy(() -> tested.validateCertificate(invalidX509EeCert))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH.getErrorMessage(PRODUCT_TYPE));
  }
}
