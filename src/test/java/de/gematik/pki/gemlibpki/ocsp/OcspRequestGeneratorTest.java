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

package de.gematik.pki.gemlibpki.ocsp;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.junit.jupiter.api.Test;

class OcspRequestGeneratorTest {

  private static final X509Certificate VALID_X509_EE_CERT =
      CertificateProvider.getX509Certificate(
          "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
  private static final X509Certificate VALID_X509_ISSUER_CERT =
      CertificateProvider.getX509Certificate(
          "src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");

  @Test
  void verifyGenerateOcspRequest() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

    assertDoesNotThrow(() -> writeOcspReqToFile(ocspReq));

    assertThat(ocspReq).isNotNull();
    assertThat(ocspReq.getRequestList()).hasSize(1);
  }

  @Test
  void nonNullTests() {
    assertThatThrownBy(
            () -> OcspRequestGenerator.generateSingleOcspRequest(null, VALID_X509_ISSUER_CERT))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509EeCert is marked non-null but is null");

    assertThatThrownBy(
            () -> OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509IssuerCert is marked non-null but is null");
  }

  private static void writeOcspReqToFile(final OCSPReq ocspReq) throws IOException {
    Files.write(TestUtils.createLogFileInTarget("ocspRequest"), ocspReq.getEncoded());
  }
}
