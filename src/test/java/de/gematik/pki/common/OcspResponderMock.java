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

package de.gematik.pki.common;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.pki.ocsp.OcspConstants;
import de.gematik.pki.ocsp.OcspResponseGenerator;
import java.security.cert.X509Certificate;
import lombok.SneakyThrows;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

public class OcspResponderMock {

    private WireMockServer wireMockServer;
    private String sspDir;
    private String ocspHost;

    public OcspResponderMock(final String sspDir, final String ocspHost) {
        this.sspDir = sspDir;
        this.ocspHost = ocspHost;
        startNewWireMockServer();
    }

    public void setSspDir(final String sspDir) {
        this.sspDir = sspDir;
    }

    public void setOcspHost(final String ocspHost) {
        this.ocspHost = ocspHost;
    }

    public void configureForOcspRequest(final OCSPReq ocspReq, final X509Certificate eeCert) {
        // build OCSP Response depending on request
        final OCSPResp ocspRespToSent = OcspResponseGenerator.builder()
            .signer(OcspConstants.getOcspSignerRsa())
            .build()
            .gen(ocspReq, eeCert);

        // configure WireMock with OCSP Response
        configureWireMockReceiveHttpPost(ocspRespToSent, HttpStatus.SC_OK);
    }

    @SneakyThrows
    public String getSspUrl() {
        return ocspHost + wireMockServer.port() + sspDir;
    }

    private void startNewWireMockServer() {
        wireMockServer = new WireMockServer(options()
            .dynamicPort()
            .dynamicHttpsPort()
        );
        wireMockServer.start();
    }

    @SneakyThrows
    private void configureWireMockReceiveHttpPost(final OCSPResp ocspRespTx, final int httpStatus) {
        wireMockServer.stubFor(post(urlEqualTo(sspDir))
            .willReturn(aResponse()
                .withStatus(httpStatus)
                .withHeader("Content-Type", "application/ocsp-response")
                .withBody(ocspRespTx.getEncoded())));
    }


}
