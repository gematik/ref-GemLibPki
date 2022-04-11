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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.utils.CertificateProvider;
import de.gematik.pki.utils.P12Reader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class OcspResponseGeneratorTest {

    final X509Certificate VALID_X509_EE_CERT = CertificateProvider.getX509Certificate(
        "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    final X509Certificate VALID_X509_ISSUER_CERT = CertificateProvider.getX509Certificate("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

    OcspResponseGeneratorTest() throws IOException, GemPkiException {
    }

    @Test
    void createRsaObject() {
        assertDoesNotThrow(() -> OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerRsa())
            .build());
    }

    @Test
    void createEccObject() {
        assertDoesNotThrow(() -> OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .build());
    }

    @SneakyThrows
    @Test
    void useOcspResp() {
        assertDoesNotThrow(() -> writeOcspRespToFile(OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT)));
    }

    @SneakyThrows
    @Test
    void useOcspRespInvalidAlgo() {
        assertThatThrownBy(() -> OcspResponseGenerator.builder()
            .signer(Objects.requireNonNull(P12Reader.getContentFromP12(Path.of("src/test/resources/certificates/ocsp/dsaCert.p12"), "00")))
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT))
            .hasMessage("Signature algorithm not supported: DSA")
            .isInstanceOf(GemPkiException.class);
    }

    @SneakyThrows
    @Test
    @DisplayName("Validate CertHash valid")
    void validateCertHashValid() {
        final OCSPResp ocspResp = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .validCertHash(true)
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT);
        final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp[] singeResponse = basicOcspResp.getResponses();
        final CertHash asn1CertHash = CertHash.getInstance(singeResponse[0].getExtension(id_isismtt_at_certHash).getParsedValue());
        assertThat(new String(Hex.encode(asn1CertHash.getCertificateHash())))
            .isEqualTo("6cda0ef261c36bc05cc66e809ea1621e1dafa794a8c8a04e114e9114689d2ff7"); // sha256 hash over der encoded end-entity certificate file
    }

    @SneakyThrows
    @Test
    @DisplayName("Validate CertHash invalid")
    void validateCertHashInvalid() {
        final OCSPResp ocspResp = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .validCertHash(false)
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT);
        final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp[] singeResponse = basicOcspResp.getResponses();
        final CertHash asn1CertHash = CertHash.getInstance(singeResponse[0].getExtension(id_isismtt_at_certHash).getParsedValue());
        assertThat(new String(Hex.encode(asn1CertHash.getCertificateHash())))
            .isEqualTo("65785b5437ef3a7a7521ba3ac418c8b05c036eeca88e53688ff460676f5288ba"); // sha256 hash from string: "notAValidCertHash"
    }

    @SneakyThrows
    @Test
    @DisplayName("Validate CertHash missing")
    void validateCertHashMissing() {
        final OCSPResp ocspResp = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .withCertHash(false)
            .build()
            .gen(ocspReq, VALID_X509_EE_CERT);
        final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
        assertThatThrownBy(() -> CertHash.getInstance(basicOcspResp.getExtension(id_isismtt_at_certHash).getParsedValue()))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Validate null parameters")
    void nonNullTests() {
        final OcspResponseGenerator ocspResponseGenerator = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerEcc())
            .build();

        assertThatThrownBy(() -> ocspResponseGenerator.gen(null, VALID_X509_EE_CERT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("ocspReq");
        assertThatThrownBy(() -> ocspResponseGenerator.gen(ocspReq, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("eeCert");
    }


    private static void writeOcspRespToFile(final OCSPResp ocspResp) throws IOException {
        Files.write(createOcspResponseLogFile(), ocspResp.getEncoded());
    }

    private static Path createOcspResponseLogFile() throws IOException {
        final Path filePath = Path.of("target/ocspResponse_" + ZonedDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")) + ".dat");
        if (Files.exists(filePath)) {
            Files.delete(filePath);
        }
        Files.createFile(filePath);
        return filePath;
    }

}
