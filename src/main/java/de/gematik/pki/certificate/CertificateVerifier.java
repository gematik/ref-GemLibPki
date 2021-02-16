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

package de.gematik.pki.certificate;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.exception.GemPkiParsingException;
import de.gematik.pki.tsl.TspService;
import java.security.cert.X509Certificate;
import java.util.EnumMap;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class CertificateVerifier {

    @NonNull
    private final String productType;
    @NonNull
    private final List<TspService> tspServiceList;
    @NonNull
    private final List<CertificateProfile> certificateProfiles;

    public CertificateType performTucPki18Checks(@NonNull final X509Certificate x509EeCert) throws GemPkiException {
        if (certificateProfiles.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.UNKNOWN);
        }

        final EnumMap<CertificateProfile, GemPkiException> errors = new EnumMap<>(CertificateProfile.class);
        for (final CertificateProfile certificateProfile : certificateProfiles) {
            try {
                SingleCertificateVerificationWorker.builder()
                    .x509EeCert(x509EeCert)
                    .certificateProfile(certificateProfile)
                    .tspServiceList(tspServiceList)
                    .productType(productType)
                    .build()
                    .performCertificateChecks();
                log.debug("Übergebenes Zertifikat wurde erfolgreich gegen das Zertifikatsprofil {} getestet.",
                    certificateProfile);
                return certificateProfile.getCertificateType();
            } catch (final RuntimeException e) {
                errors.put(certificateProfile, new GemPkiException(productType, ErrorCode.UNKNOWN, e));
            } catch (final GemPkiException e) {
                errors.put(certificateProfile, e);
            }
        }
        throw new GemPkiParsingException(productType, errors);
    }
}
