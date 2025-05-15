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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen
 * wäre vermutlich akademisch.
 */
class CertificateCommonVerificationTest {

  @Test
  void verifyValid() throws GemPkiException {

    final ZonedDateTime zonedDateTime = ZonedDateTime.parse("2025-03-20T15:00:00Z");

    final List<TspService> tspServices =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT))
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
}
