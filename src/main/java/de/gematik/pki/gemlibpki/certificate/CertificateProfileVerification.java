/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.certificate;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.validators.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;

/**
 * Class for verification checks on a certificate against a profile. This class works with
 * parameterized variables (defined by builder pattern) and with given variables provided by runtime
 * (method parameters).
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public final class CertificateProfileVerification {

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;
    @NonNull
    private final CertificateProfile certificateProfile;
    @NonNull
    private final X509Certificate x509EeCert;

    /**
     * Perform all verification checks
     *
     * @throws GemPkiException thrown if cert cannot be verified according to KeyUsage, ExtKeyUsage or
     *                         CertType
     */
    public void verifyAll() throws GemPkiException {

        new KeyUsageValidator(productType).validateCertificate(x509EeCert, certificateProfile);
        new ExtendedKeyUsageValidator(productType).validateCertificate(x509EeCert, certificateProfile);

        new CertificateProfileByCertificateTypeOidValidator(productType).validateCertificate(x509EeCert, certificateProfile);
        new CertificateTypeOidInIssuerTspServiceExtensionValidator(productType, tspServiceSubset).validateCertificate(x509EeCert, certificateProfile);

        new CriticalExtensionsValidator(productType).validateCertificate(x509EeCert, certificateProfile);
    }

}
