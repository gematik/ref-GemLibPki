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

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Class to send OCSP requests and receive OCSP responses
 */
@Slf4j
@RequiredArgsConstructor
@Builder
public class OcspTransceiver {

    private final X509Certificate x509EeCert;
    private final X509Certificate x509IssuerCert;
    private final URL url;

    /**
     * Verifies OCSP status of end-entity certificate. Operates on member variables given by builder.
     *
     * @return True if certificate status is GOOD.
     * @throws GemPkiException
     */
    public boolean verifyOcspStatusGood()
        throws GemPkiException {
        return OcspVerifier
            .isStatusGood(sendOcspRequest(url, OcspRequestGenerator.generateSingleOcspRequest(x509EeCert,
                x509IssuerCert)));
    }

    /**
     * Sends given OCSP request to given URL.
     *
     * @param url     SSP URL to sent to
     * @param request OCSP request to sent
     * @return received OCSP response
     * @throws GemPkiException
     */
    public OCSPResp sendOcspRequest(final URL url, final OCSPReq request) throws GemPkiException {
        final HttpResponse<InputStream> httpResponse;
        try {
            httpResponse = Unirest.post(url.toString())
                .header("Content-Type", "application/ocsp-request").body(request.getEncoded()).asBinary();
            return new OCSPResp(httpResponse.getBody().readAllBytes());
        } catch (final UnirestException | IOException e) {
            throw new GemPkiException(ErrorCode.OCSP, "OCSP senden/empfangen fehlgeschlagen", e);
        }
    }
}
