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

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.bouncycastle.cert.ocsp.*;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OcspVerifier {

    /**
     * @param ocspResponse OCSP Response
     * @return True if certificate status of first single response in OCSP response has status GOOD
     * @throws GemPkiException exception thrown if ocsp response cannot be evaluated
     */
    public static boolean isStatusGood(@NonNull final OCSPResp ocspResponse) throws GemPkiException {
        if (ocspResponse.getStatus() != 0) {
            return false;
        }
        final BasicOCSPResp basicResponse;
        try {
            basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
        } catch (final OCSPException e) {
            throw new GemPkiException(ErrorCode.OCSP, "OCSP response Auswertung fehlgeschlagen", e);
        }
        if (basicResponse != null) {
            final SingleResp[] responses = basicResponse.getResponses();
            if (responses.length == 1) {
                final SingleResp resp = responses[0];
                return CertificateStatus.GOOD == resp.getCertStatus();
            }
        }
        return false;
    }
}
