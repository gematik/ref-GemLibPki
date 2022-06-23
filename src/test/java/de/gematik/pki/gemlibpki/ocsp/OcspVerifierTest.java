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

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspVerifierTest {

  private static X509Certificate VALID_X509_EE_CERT;
  private static X509Certificate VALID_X509_ISSUER_CERT;
  private static OCSPReq ocspReq;

  @BeforeAll
  public static void start() {
    VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    VALID_X509_ISSUER_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
  }

  @Test
  void verifyCertificateStatusGood() {
    assertDoesNotThrow(() -> genDefaultOcspVerifier().verifyStatusGood());
  }

  @Test
  void verifyCertHashValid() {
    assertDoesNotThrow(() -> genDefaultOcspVerifier().verifyCertHash());
  }

  @Test
  void verifyCertHashInValid() {
    assertThatThrownBy(
            () ->
                OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .eeCert(VALID_X509_ISSUER_CERT)
                    .ocspResponse(genDefaultOcspResp())
                    .build()
                    .verifyCertHash())
        .hasMessage(ErrorCode.SE_1041.getErrorMessage(PRODUCT_TYPE))
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void verifyCertHashMissing() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerRsa())
            .withCertHash(false)
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT);
    assertThatThrownBy(
            () ->
                OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .eeCert(VALID_X509_EE_CERT)
                    .ocspResponse(ocspRespLocal)
                    .build()
                    .verifyCertHash())
        .hasMessage(ErrorCode.SE_1040.getErrorMessage(PRODUCT_TYPE))
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void nonNullTests() {
    final OcspVerifier.OcspVerifierBuilder builder = OcspVerifier.builder();

    assertThatThrownBy(() -> builder.productType(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("productType is marked non-null but is null");

    assertThatThrownBy(() -> builder.eeCert(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("eeCert");

    assertThatThrownBy(() -> builder.ocspResponse(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("ocspResponse");
  }

  private static OCSPResp genDefaultOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspConstants.getOcspSignerRsa())
        .build()
        .gen(ocspReq, VALID_X509_EE_CERT);
  }

  private OcspVerifier genDefaultOcspVerifier() {
    return OcspVerifier.builder()
        .productType(PRODUCT_TYPE)
        .eeCert(VALID_X509_EE_CERT)
        .ocspResponse(genDefaultOcspResp())
        .build();
  }
}
