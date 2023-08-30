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

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

class OcspRequestGeneratorTest {

  @Test
  void verifyGenerateOcspRequest() {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    assertDoesNotThrow(() -> writeOcspReqToFile(ocspReq));

    assertThat(ocspReq).isNotNull();
    assertThat(ocspReq.getRequestList()).hasSize(1);
  }

  @Test
  void nonNullTests() {
    assertNonNullParameter(
        () -> OcspRequestGenerator.generateSingleOcspRequest(null, VALID_ISSUER_CERT_SMCB),
        "x509EeCert");

    assertNonNullParameter(
        () -> OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT_SMCB, null),
        "x509IssuerCert");

    assertNonNullParameter(
        () ->
            OcspRequestGenerator.generateSingleOcspRequest(
                null, VALID_ISSUER_CERT_SMCB, CertificateID.HASH_SHA1),
        "x509EeCert");

    assertNonNullParameter(
        () ->
            OcspRequestGenerator.generateSingleOcspRequest(
                VALID_X509_EE_CERT_SMCB, null, CertificateID.HASH_SHA1),
        "x509IssuerCert");

    assertNonNullParameter(
        () ->
            OcspRequestGenerator.generateSingleOcspRequest(
                VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, null),
        "algorithmIdentifier");

    assertNonNullParameter(
        () ->
            OcspRequestGenerator.createCertificateId(
                null, VALID_ISSUER_CERT_SMCB, CertificateID.HASH_SHA1),
        "serialNumber");
    assertNonNullParameter(
        () ->
            OcspRequestGenerator.createCertificateId(
                VALID_X509_EE_CERT_SMCB.getSerialNumber(), null, CertificateID.HASH_SHA1),
        "x509IssuerCert");
    assertNonNullParameter(
        () ->
            OcspRequestGenerator.createCertificateId(
                VALID_X509_EE_CERT_SMCB.getSerialNumber(), VALID_ISSUER_CERT_SMCB, null),
        "algorithmIdentifier");
  }

  private static void writeOcspReqToFile(final OCSPReq ocspReq) throws IOException {
    Files.write(TestUtils.createLogFileInTarget("ocspRequest"), ocspReq.getEncoded());
  }

  @Test
  void verifyCreateCertificateIdException() throws CertificateEncodingException {

    final X509Certificate issuerCertSpy = Mockito.spy(VALID_ISSUER_CERT_SMCB);
    Mockito.doThrow(CertificateEncodingException.class).when(issuerCertSpy).getEncoded();

    final BigInteger serialNumber = VALID_X509_EE_CERT_SMCB.getSerialNumber();

    assertThatThrownBy(
            () ->
                OcspRequestGenerator.createCertificateId(
                    serialNumber, issuerCertSpy, CertificateID.HASH_SHA1))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Generieren der OCSP CertID fehlgeschlagen.");
  }

  @Test
  void verifyGenerateSingleOcspRequestException() {

    try (final MockedConstruction<OCSPReqBuilder> ignored =
        Mockito.mockConstruction(
            OCSPReqBuilder.class,
            (mock, context) -> Mockito.when(mock.build()).thenThrow(OCSPException.class))) {

      assertThatThrownBy(
              () ->
                  OcspRequestGenerator.generateSingleOcspRequest(
                      VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, CertificateID.HASH_SHA1))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Generieren des OCSP Requests fehlgeschlagen.")
          .cause()
          .isInstanceOf(OCSPException.class);
    }
  }
}
