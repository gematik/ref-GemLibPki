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

import static de.gematik.pki.utils.Utils.calculateSha256;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.cert.ocsp.*;

/**
 * Entry point to access a verification of ocspresponses regarding standard process called TucPki006. This class works with parameterized variables (defined by
 * builder pattern) and with given variables provided by runtime (method parameters).
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class OcspVerifier {

    @NonNull
    private final String productType;
    @NonNull
    final X509Certificate eeCert;
    @NonNull
    final OCSPResp ocspResponse;

    public void performOcspChecks() throws GemPkiException {
        // TODO create new OCSP checks: OCSP_CHECK_REVOCATION_FAILED, OCSP_CHECK_REVOCATION_ERROR, OCSP_NOT_AVAILABLE...
        verifyCertHash();
        verifyStatusGood();
    }

    /**
     * @throws GemPkiException exception thrown if ocsp response cannot be evaluated
     */
    public void verifyStatusGood() throws GemPkiException {
        if (ocspResponse.getStatus() != 0) {
            throw new GemPkiException(ErrorCode.OCSP, "OCSP response status ist nicht 0, sondern: " + ocspResponse.getStatus());
        }
        final BasicOCSPResp basicResponse;
        try {
            basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
        } catch (final OCSPException e) {
            throw new GemPkiException(ErrorCode.OCSP, "OCSP response Auswertung fehlgeschlagen", e);
        }
        if (basicResponse != null) {
            final SingleResp[] responses = basicResponse.getResponses();
            if (responses.length != 1) {
                throw new GemPkiException(ErrorCode.OCSP, "Mehr als eine OCSP Response erhalten: " + responses.length);
            } else {
                if (CertificateStatus.GOOD != responses[0].getCertStatus()) {
                    throw new GemPkiException(ErrorCode.OCSP, "OCSP Response ist nicht GOOD, sondern: " + responses[0].getCertStatus());
                }
            }
        } else {
            throw new GemPkiException(ErrorCode.OCSP, "Keine OCSP Response erhalten.");
        }

    }

    public void verifyCertHash() throws GemPkiException {
        try {
            final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResponse.getResponseObject();
            final SingleResp[] singleResponse = basicOcspResp.getResponses();
            final CertHash asn1CertHash = CertHash.getInstance(singleResponse[0].getExtension(id_isismtt_at_certHash).getParsedValue());
            if (!Arrays.equals(asn1CertHash.getCertificateHash(), calculateSha256(eeCert.getEncoded()))) {
                throw new GemPkiException(productType, ErrorCode.SE_1041);
            }
        } catch (final NullPointerException e) {
            throw new GemPkiException(productType, ErrorCode.SE_1040);
        } catch (final CertificateEncodingException | OCSPException e) {
            throw new GemPkiException(ErrorCode.OCSP, "OCSP Response Auswertung fehlgeschlagen", e);
        }
    }

}
