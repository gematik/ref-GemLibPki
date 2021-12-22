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
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import de.gematik.pki.common.OcspResponderMock;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
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
    private final static String LOCAL_SSP_DIR = "/services/ocsp";
    private final static String OCSP_HOST = "http://localhost:";
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
    void verifyOcspStatusExpectedGood() throws GemPkiException {
        configureOcspResponderMockForOcspRequest();
        assertThat(
            OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp(ocspResponderMock.getSspUrl())
                .build()
                .verifyOcspStatusGood(null)).isTrue();
    }

    @Test
    void verifySspUrlInvalidThrowsGemPkiExceptionOnly() {
        assertThatThrownBy(
            () -> OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .ssp("http://no/wiremock/started")
                .build()
                .verifyOcspStatusGood(null))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining("OCSP senden/empfangen fehlgeschlagen");
    }

    @Test
    void sendOcspRequestReceiveOcspResponseGood() throws GemPkiException {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
        final OCSPResp ocspRespRx = OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .ssp(ocspResponderMock.getSspUrl())
            .build()
            .sendOcspRequest(ocspReq);

        assertThat(ocspReq).isNotNull();
        assertThat(OcspVerifier.isStatusGood(ocspRespRx)).isTrue();
    }

    @Test
    void sendOcspRequestReceiveOcspResponseGoodStatic() throws GemPkiException {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();
        final OCSPResp ocspRespRx = OcspTransceiver.sendOcspRequestToUrl(ocspResponderMock.getSspUrl(), ocspReq);

        assertThat(ocspReq).isNotNull();
        assertThat(OcspVerifier.isStatusGood(ocspRespRx)).isTrue();
    }

    @SneakyThrows
    @Test
    void sendOcspRequestUnreachableUrl() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

        assertThatThrownBy(() -> OcspTransceiver.sendOcspRequestToUrl("http://127.0.0.1:4545/unreachable", ocspReq))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.OCSP.name());
    }

    /**
     * OcspResponderMock will send OcspResponse with HttpStatus 404
     */
    @SneakyThrows
    @Test
    void sendOcspRequestUnknownEndpoint() {
        final OCSPReq ocspReq = configureOcspResponderMockForOcspRequest();

        assertThatThrownBy(() -> OcspTransceiver.sendOcspRequestToUrl(ocspResponderMock.getSspUrl() + "unknownEndpoint", ocspReq))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining(ErrorCode.OCSP.name());
    }


    private OCSPReq configureOcspResponderMockForOcspRequest()
        throws GemPkiException {
        final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT,
            VALID_X509_ISSUER_CERT);
        ocspResponderMock.configureForOcspRequest(ocspReq);
        return ocspReq;
    }

}
