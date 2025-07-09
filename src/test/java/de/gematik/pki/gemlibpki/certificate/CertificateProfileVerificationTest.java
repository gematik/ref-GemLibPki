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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.Test;

class CertificateProfileVerificationTest {

  @Test
  void verifyValid() throws GemPkiException {

    final String productType = "IDP";

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(
                new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT))
                    .getTspServices(),
                productType)
            .getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB);

    final CertificateProfileVerification tested =
        CertificateProfileVerification.builder()
            .productType(productType)
            .x509EeCert(VALID_X509_EE_CERT_SMCB)
            .certificateProfile(CERT_PROFILE_C_HCI_AUT_ECC)
            .tspServiceSubset(tspServiceSubset)
            .build();
    assertDoesNotThrow(tested::verifyAll);
  }
}
