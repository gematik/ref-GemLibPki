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

package de.gematik.pki.certificate;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.tsl.TspServiceSubset;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Class for common verification checks on a certificate. This class works with parameterized variables (defined by builder pattern) and with given variables
 * provided by runtime (method parameters).
 */

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class CertificateCommonVerification {

    public static final String SVCSTATUS_REVOKED = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked";

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;
    @NonNull
    private final X509Certificate x509EeCert;

    public void verifyValidity() throws GemPkiException {
        verifyValidity(ZonedDateTime.now());
    }

    /**
     * Verify validity period of parameterized end-entity certificate against a given reference date.
     *
     * @param referenceDate date to check against
     * @throws GemPkiException if certificate is not valid in time
     */
    public void verifyValidity(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {

        if (!(x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC).isBefore(referenceDate) &&
            x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC)
                .isAfter(referenceDate))) {
            log.debug(
                "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitsbereichs des Zertifikates.", referenceDate);
            throw new GemPkiException(productType, ErrorCode.SE_1021); //CERTIFICATE_NOT_VALID_TIME
        }
    }

    /**
     * Verify signature of parameterized end-entity certificate against given issuer certificate. Issuer certificate (CA) is determined from TSL file.
     *
     * @param x509IssuerCert issuer certificate
     * @throws GemPkiException if certificate is mathematically invalid
     */
    public void verifySignature(@NonNull final X509Certificate x509IssuerCert) throws GemPkiException {
        try {
            x509EeCert.verify(x509IssuerCert.getPublicKey());
            log.debug("Signaturprüfung von {} erfolgreich", x509EeCert.getSubjectX500Principal());
        } catch (final GeneralSecurityException verifyFailed) {
            throw new GemPkiException(productType, ErrorCode.SE_1024, verifyFailed); //CERTIFICATE_NOT_VALID_MATH
        }
    }

    // ####################  Start issuer checks #########################################################

    /**
     * Verify issuer service status from tsl file. The status determines if an end-entity certificate was issued after the CA (Issuer) was revoked.
     *
     * @throws GemPkiException if certificate has been revoked
     */
    public void verifyIssuerServiceStatus() throws GemPkiException {
        if (tspServiceSubset.getServiceStatus().equals(SVCSTATUS_REVOKED)) {
            final ZonedDateTime statusStartingTime = tspServiceSubset.getStatusStartingTime();
            if (statusStartingTime.isBefore(x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC))) {
                throw new GemPkiException(productType, ErrorCode.SE_1036);
            }
        }
    }

    // ####################  End issuer checks ########################################################

}
