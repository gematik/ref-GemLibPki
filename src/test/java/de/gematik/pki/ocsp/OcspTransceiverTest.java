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

import static de.gematik.pki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.TestConstants.OCSP_HOST;
import static de.gematik.pki.TestConstants.PRODUCT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import de.gematik.pki.common.OcspResponderMock;
import de.gematik.pki.exception.GemPkiRuntimeException;
import de.gematik.pki.utils.CertificateProvider;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspTransceiverTest {

    private static X509Certificate VALID_X509_EE_CERT;
    private static X509Certificate VALID_X509_ISSUER_CERT;
    private static OcspResponderMock ocspResponderMock;

    @SneakyThrows
    @BeforeAll
    public static void start() {
        ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
        VALID_X509_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_X509_ISSUER_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    }

    @Test
    void verifyOcspStatusExpectedGood() {
        configureOcspResponderMockForOcspRequest();
        assertDoesNotThrow(() ->
            OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp(ocspResponderMock.getSspUrl())
                .productType(PRODUCT_TYPE)
                .build()
                .verifyOcspResponse(null));
    }

    @Test
    void verifyOcspStatusExpectedGoodFromCache() {
        configureOcspResponderMockForOcspRequest();
        final OCSPResp ocspResp = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerRsa())
            .build()
            .gen(OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT), VALID_X509_EE_CERT);
        final OcspRespCache cache = new OcspRespCache(10);
        cache.saveResponse(VALID_X509_EE_CERT.getSerialNumber(), ocspResp);
        assertDoesNotThrow(() ->
            OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp("http://invalid.url") //to see, if cached response is used
                .productType(PRODUCT_TYPE)
                .build()
                .verifyOcspResponse(cache));
    }

    @Test
    void verifySspUrlInvalidThrowsGemPkiExceptionOnly() {
        final var builder = OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp("https://no/wiremock/started")
            .productType(PRODUCT_TYPE)
            .build();
        assertThatThrownBy(() -> builder.verifyOcspResponse(null))
            .isInstanceOf(GemPkiRuntimeException.class)
            .hasMessage("OCSP senden/empfangen fehlgeschlagen.");
    }

    @Test
    void sendOcspRequestReceiveOcspResponseGood() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
        final OCSPResp ocspRespRx = OcspTransceiver.builder()
            .x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp(ocspResponderMock.getSspUrl()
            )
            .productType(PRODUCT_TYPE)
            .build()
            .sendOcspRequest(ocspReq);

        assertThat(ocspReq).isNotNull();
        assertDoesNotThrow(() -> OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .eeCert(VALID_X509_EE_CERT)
            .ocspResponse(ocspRespRx).build()
            .verifyStatusGood()
        );
    }

    @Test
    void sendOcspRequestReceiveOcspResponseGoodStatic() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
        final OCSPResp ocspRespRx = OcspTransceiver.sendOcspRequestToUrl(ocspResponderMock.getSspUrl(), ocspReq);

        assertThat(ocspReq).isNotNull();
        assertDoesNotThrow(() -> OcspVerifier.builder()
            .eeCert(VALID_X509_EE_CERT)
            .ocspResponse(ocspRespRx).productType(PRODUCT_TYPE).build().verifyStatusGood());
    }

    @SneakyThrows
    @Test
    void sendOcspRequestUnreachableUrl() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

        assertThatThrownBy(() -> OcspTransceiver.sendOcspRequestToUrl("http://127.0.0.1:4545/unreachable", ocspReq))
            .isInstanceOf(GemPkiRuntimeException.class)
            .hasMessage("OCSP senden/empfangen fehlgeschlagen.");
    }

    /**
     * OcspResponderMock will send OcspResponse with HttpStatus 404
     */
    @SneakyThrows
    @Test
    void sendOcspRequestUnknownEndpoint() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
        final String ssp = ocspResponderMock.getSspUrl() + "unknownEndpoint";
        assertThatThrownBy(() -> OcspTransceiver.sendOcspRequestToUrl(ssp, ocspReq))
            .isInstanceOf(GemPkiRuntimeException.class)
            .hasMessage("OCSP senden/empfangen fehlgeschlagen.");
    }

    private OCSPReq configureOcspResponderMockForOcspRequest() {
        final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT,
            VALID_X509_ISSUER_CERT);
        ocspResponderMock.configureForOcspRequest(ocspReq, VALID_X509_EE_CERT);
        return ocspReq;
    }

}
