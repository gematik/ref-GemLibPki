/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.common;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspTestConstants;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import lombok.SneakyThrows;
import org.apache.hc.core5.http.HttpHeaders;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

public class OcspResponderMock {

  private WireMockServer wireMockServer;
  private final String sspDir;
  private final String ocspHost;

  public OcspResponderMock(final String sspDir, final String ocspHost) {
    this.sspDir = sspDir;
    this.ocspHost = ocspHost;
    startNewWireMockServer();
  }

  /**
   * Configures WireMock with OCSP Response generated from provided OCSP request and end-entity
   * certificate
   *
   * @param ocspReq OCSP request
   * @param eeCert end-entity certificate
   */
  public void configureForOcspRequest(
      final OCSPReq ocspReq, final X509Certificate eeCert, final X509Certificate issuerCert) {
    // build OCSP Response depending on request
    final OCSPResp ocspRespToSent =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, eeCert, issuerCert);
    // configure WireMock with OCSP Response
    configureWireMockReceiveHttpPost(ocspRespToSent, HttpURLConnection.HTTP_OK);
  }

  /**
   * Configures WireMock with OCSP Response generated from provided end-entity and issuer
   * certificates
   *
   * @param eeCert end-entity certificate
   * @param issuerCert issuer certificate
   */
  public void configureForOcspRequest(
      final X509Certificate eeCert, final X509Certificate issuerCert) {

    final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(eeCert, issuerCert);
    configureForOcspRequest(ocspReq, eeCert, issuerCert);
  }

  public void configureForOcspRequestProducedAt(
      final X509Certificate eeCert,
      final X509Certificate issuerCert,
      final int producedAtDeltaMilliseconds) {

    final OCSPReq ocspReq = OcspRequestGenerator.generateSingleOcspRequest(eeCert, issuerCert);
    final OCSPResp ocspRespToSent =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(ZonedDateTime.now().plus(producedAtDeltaMilliseconds, ChronoUnit.MILLIS))
            .build()
            .generate(ocspReq, eeCert, issuerCert);
    configureWireMockReceiveHttpPost(ocspRespToSent, HttpURLConnection.HTTP_OK);
  }

  public String getSspUrl() {
    return ocspHost + wireMockServer.port() + sspDir;
  }

  private void startNewWireMockServer() {
    wireMockServer = new WireMockServer(options().dynamicPort());
    wireMockServer.start();
  }

  @SneakyThrows
  public void configureWireMockReceiveHttpPost(final OCSPResp ocspRespTx, final int httpStatus) {
    wireMockServer.stubFor(
        post(urlEqualTo(sspDir))
            .willReturn(
                aResponse()
                    .withStatus(httpStatus)
                    .withHeader(
                        HttpHeaders.CONTENT_TYPE,
                        OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
                    .withBody(ocspRespTx.getEncoded())));
  }
}
