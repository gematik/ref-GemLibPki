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

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

/** Class to send OCSP requests and receive OCSP responses */
@Slf4j
@RequiredArgsConstructor
@Builder
public class OcspTransceiver {

  @NonNull private final X509Certificate x509EeCert;
  @NonNull private final X509Certificate x509IssuerCert;
  @NonNull private final String ssp;
  @NonNull private final String productType;

  /**
   * Verifies OCSP status of end-entity certificate. Sends OCSP request if OCSP response is not
   * cached.
   *
   * @param ocspRespCache Cache for OCSP Responses
   * @throws GemPkiException during ocsp checks
   */
  public void verifyOcspResponse(final OcspRespCache ocspRespCache) throws GemPkiException {
    if (ocspRespCache != null) {
      final Optional<OCSPResp> cached = ocspRespCache.getResponse(x509EeCert.getSerialNumber());
      if (cached.isPresent()) {
        OcspVerifier.builder()
            .productType(productType)
            .eeCert(x509EeCert)
            .ocspResponse(cached.get())
            .build()
            .verifyStatusGood();
      } else {
        verifyOcspResponseOnline();
      }
    } else {
      verifyOcspResponseOnline();
    }
  }

  /**
   * Verifies OCSP status of end-entity certificate by sending an OCSP request. Operates on member
   * variables given by builder.
   *
   * @throws GemPkiException during ocsp checks
   */
  private void verifyOcspResponseOnline() throws GemPkiException {
    OcspVerifier.builder()
        .productType(productType)
        .eeCert(x509EeCert)
        .ocspResponse(
            sendOcspRequest(
                OcspRequestGenerator.generateSingleOcspRequest(x509EeCert, x509IssuerCert)))
        .build()
        .performOcspChecks();
  }

  /**
   * Sends given OCSP request.
   *
   * @param request OCSP request to sent
   * @return received OCSP response
   */
  public OCSPResp sendOcspRequest(final OCSPReq request) {
    return sendOcspRequestToUrl(ssp, request);
  }

  /**
   * Sends given OCSP request to given SSP. For use without response validation.
   *
   * @param ssp SSP URL to sent to
   * @param request OCSP request to sent
   * @return received OCSP response
   */
  public static OCSPResp sendOcspRequestToUrl(final String ssp, final OCSPReq request) {
    final HttpResponse<byte[]> httpResponse;
    try {
      log.info(
          "Send OCSP Request for certificate serial number: "
              + request.getRequestList()[0].getCertID().getSerialNumber()
              + " to: "
              + ssp);
      httpResponse =
          Unirest.post(ssp)
              .header("Content-Type", "application/ocsp-request")
              .body(request.getEncoded())
              .asBytes();
      log.info("HttpStatus der OcspResponse: " + httpResponse.getStatus());
      return new OCSPResp(httpResponse.getBody());
    } catch (final UnirestException | IOException e) {
      throw new GemPkiRuntimeException("OCSP senden/empfangen fehlgeschlagen.", e);
    }
  }
}
