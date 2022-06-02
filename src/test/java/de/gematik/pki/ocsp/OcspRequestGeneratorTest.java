/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.ocsp;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import de.gematik.pki.utils.CertificateProvider;
import java.io.IOException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspRequestGeneratorTest {

    private static X509Certificate VALID_X509_EE_CERT;
    private static X509Certificate VALID_X509_ISSUER_CERT;

    @BeforeAll
    public static void start() throws IOException {
        VALID_X509_EE_CERT = CertificateProvider.getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_X509_ISSUER_CERT = CertificateProvider.getX509Certificate("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    }

    @Test
    void verifyGenerateOCSPRequest() {
        final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
        assertThat(ocspReq).isNotNull();
        assertThat(ocspReq.getRequestList()).hasSize(1);
    }

    @Test
    void nonNullTests() {
        assertThatThrownBy(
            () -> OcspRequestGenerator.generateSingleOcspRequest(null, VALID_X509_ISSUER_CERT))
            .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(
            () -> OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, null))
            .isInstanceOf(NullPointerException.class);
    }
}
