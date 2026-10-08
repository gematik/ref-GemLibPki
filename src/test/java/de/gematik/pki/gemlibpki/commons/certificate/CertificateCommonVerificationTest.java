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

package de.gematik.pki.gemlibpki.commons.certificate;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.commons.validators.IssuerServiceStatusValidator;
import de.gematik.pki.gemlibpki.commons.validators.ShellModelValidator;
import de.gematik.pki.gemlibpki.commons.validators.SignatureValidator;
import de.gematik.pki.gemlibpki.commons.validators.ValidityValidator;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen
 * wäre vermutlich akademisch.
 */
class CertificateCommonVerificationTest {

  @Test
  void verifyAll_whenCertificateAndTspServiceSubsetAreValid_thenCompletesWithoutException()
      throws GemPkiException {

    final ZonedDateTime zonedDateTime = ZonedDateTime.parse("2025-03-20T15:00:00Z");

    final List<TspService> tspServices =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_DEFAULT_NON_QES))
            .getTspServices();
    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServices, PRODUCT_TYPE)
            .getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB);

    final CertificateCommonVerification tested =
        CertificateCommonVerification.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .tspServiceSubset(tspServiceSubset)
            .referenceDate(zonedDateTime)
            .build();

    assertDoesNotThrow(tested::verifyAll);
  }

  @Test
  void verifyAll_whenValidatorsAreInjected_thenAllValidatorsAreInvoked() throws GemPkiException {
    final X509Certificate x509EeCert = Mockito.mock(X509Certificate.class);
    final TspServiceSubset tspServiceSubset = Mockito.mock(TspServiceSubset.class);
    final ZonedDateTime referenceDate = ZonedDateTime.parse("2025-03-20T15:00:00Z");
    final ValidityValidator validityValidator = Mockito.mock(ValidityValidator.class);
    final SignatureValidator signatureValidator = Mockito.mock(SignatureValidator.class);
    final IssuerServiceStatusValidator issuerServiceStatusValidator =
        Mockito.mock(IssuerServiceStatusValidator.class);
    final ShellModelValidator shellModelValidator = Mockito.mock(ShellModelValidator.class);

    final CertificateCommonVerification tested =
        CertificateCommonVerification.builder()
            .productType(PRODUCT_TYPE)
            .x509EeCert(x509EeCert)
            .tspServiceSubset(tspServiceSubset)
            .referenceDate(referenceDate)
            .validityValidator(validityValidator)
            .signatureValidator(signatureValidator)
            .issuerServiceStatusValidator(issuerServiceStatusValidator)
            .shellModelValidator(shellModelValidator)
            .build();

    tested.verifyAll();

    Mockito.verify(validityValidator).validateCertificate(x509EeCert, referenceDate);
    Mockito.verify(signatureValidator).validateCertificate(x509EeCert, referenceDate);
    Mockito.verify(shellModelValidator).validateCertificate(x509EeCert, referenceDate);
    Mockito.verify(issuerServiceStatusValidator).validateCertificate(x509EeCert, referenceDate);
  }
}
