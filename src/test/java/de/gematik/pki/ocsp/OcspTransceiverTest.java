/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.ocsp;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.utils.CertificateProvider;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspTransceiverTest {

    private static X509Certificate VALID_X509_EE_CERT;
    private static X509Certificate VALID_X509_ISSUER_CERT;
    private static WireMockServer wireMockServer;
    private final static String LOCAL_SSP_DIR = "/services/ocsp";
    private final static String OCSP_HOST = "http://localhost:";
    private static URL ocspSspUrl;

    @BeforeAll
    public static void start() throws Exception {
        startNewWireMockServer();
        assignOcspSspUrl();

        VALID_X509_EE_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
        VALID_X509_ISSUER_CERT = CertificateProvider
            .getX509Certificate("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    }

    @Test
    void verifyOcspStatusExpectedGood() throws GemPkiException {
        configureWireMockForOcspRequest();
        assertThat(
            OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .url(ocspSspUrl)
                .build()
                .verifyOcspStatusGood()).isTrue();
    }

    @Test
    void verifySspUrlInvalidThrowsGemPkiExceptionOnly() {
        assertThatThrownBy(
            () -> OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT).x509IssuerCert(VALID_X509_ISSUER_CERT)
                .url(new URL("http://no/wiremock/started"))
                .build()
                .verifyOcspStatusGood())
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining("OCSP senden/empfangen fehlgeschlagen");
    }

    @Test
    void sendOcspRequestReceiveOcspResponseGood() throws GemPkiException {
        final OCSPReq ocspReq = configureWireMockForOcspRequest();
        final OCSPResp ocspRespRx = OcspTransceiver.builder().x509EeCert(VALID_X509_EE_CERT)
            .x509IssuerCert(VALID_X509_ISSUER_CERT)
            .url(ocspSspUrl)
            .build()
            .sendOcspRequest(ocspSspUrl, ocspReq);

        assertThat(ocspReq).isNotNull();
        assertThat(OcspVerifier.isStatusGood(ocspRespRx)).isTrue();
    }

    private OCSPReq configureWireMockForOcspRequest()
        throws GemPkiException {
        final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT,
            VALID_X509_ISSUER_CERT);
        // build OCSP Response depending on request
        final OCSPResp ocspRespToSent;
        try {
            ocspRespToSent = new OcspResponse().gen(ocspReq);
        } catch (final OperatorCreationException | IOException | CertificateEncodingException | OCSPException e) {
            throw new RuntimeException(e);
        }
        // configure WireMock with OCSP Response
        configureWireMockReceiveHttpPost(ocspRespToSent, 200);
        return ocspReq;
    }

    private static void startNewWireMockServer() {
        wireMockServer = new WireMockServer(options()
            .dynamicPort()
            .dynamicHttpsPort()
        );
        wireMockServer.start();
    }

    @SneakyThrows
    private void configureWireMockReceiveHttpPost(final OCSPResp ocspRespTx, final int httpStatus) {
        wireMockServer.stubFor(post(urlEqualTo(LOCAL_SSP_DIR))
            .willReturn(aResponse()
                .withStatus(httpStatus)
                .withHeader("Content-Type", "application/ocsp-response")
                .withBody(ocspRespTx.getEncoded())));
    }

    @SneakyThrows
    private static void assignOcspSspUrl() {
        ocspSspUrl = new URL(OCSP_HOST + wireMockServer.port() + LOCAL_SSP_DIR);
        System.out.println("Expected OCSP SSP: " + ocspSspUrl);
    }

}
