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
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class CriticalExtensionsValidatorTest {

  @Test
  void verifyConstructorNullParameter() {
    assertNonNullParameter(() -> new CriticalExtensionsValidator(null), "productType");
  }

  @Test
  void verifyValidateCertificateNullParameter() {
    final X509Certificate x509EeCert = Mockito.mock(X509Certificate.class);

    final CriticalExtensionsValidator tested = new CriticalExtensionsValidator(PRODUCT_TYPE);

    assertNonNullParameter(
        () -> tested.validateCertificate(null, CERT_PROFILE_C_HCI_AUT_ECC), "x509EeCert");
    assertNonNullParameter(
        () -> tested.validateCertificate(x509EeCert, null), "certificateProfile");
  }

  @Test
  void verifyCriticalExtensions() {
    final X509Certificate certInvalidCriticalExtension =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-extension-crit.pem");

    final CriticalExtensionsValidator tested = new CriticalExtensionsValidator(PRODUCT_TYPE);

    assertThatThrownBy(
            () ->
                tested.validateCertificate(
                    certInvalidCriticalExtension, CERT_PROFILE_C_HCI_AUT_ECC))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION.getErrorMessage(PRODUCT_TYPE));
  }
}
