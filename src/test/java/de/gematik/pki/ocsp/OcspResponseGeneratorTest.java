/*
 * Copyright (c) 2021 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
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
            .gen(ocspReq)));
    }

    @SneakyThrows
    @Test
    void useOcspRespInvalidAlgo() {
        assertThatThrownBy(() -> OcspResponseGenerator.builder()
            .signer(Objects.requireNonNull(P12Reader.getContentFromP12(Files.readAllBytes(Path.of("src/test/resources/certificates/ocsp/dsaCert.p12")), "00")))
            .build()
            .gen(ocspReq))
            .hasMessage("Signature algorithm not supported: DSA")
            .isInstanceOf(GemPkiException.class);
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
