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

package de.gematik.pki.gemlibpki.certificate;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.List;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen
 * wäre vermutlich akademisch.
 */
class CertificateCommonVerificationTest {


    @Test
    void verifyValid() throws GemPkiException {

        ZonedDateTime zonedDateTime = ZonedDateTime.parse("2020-11-20T15:00:00Z");

        List<TspService> tspServices = new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT)).getTspServices();
        TspServiceSubset tspServiceSubset = new TspInformationProvider(tspServices, PRODUCT_TYPE).getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB);

        CertificateCommonVerification tested = CertificateCommonVerification.builder()
                .productType(PRODUCT_TYPE)
                .x509EeCert(VALID_X509_EE_CERT_SMCB)
                .tspServiceSubset(tspServiceSubset)
                .referenceDate(zonedDateTime)
                .build();

        assertDoesNotThrow(tested::verifyAll);
    }

}
