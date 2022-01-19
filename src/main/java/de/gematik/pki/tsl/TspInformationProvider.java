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

package de.gematik.pki.tsl;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * Class to extract and compose information about a {@link TspService}.
 */
@RequiredArgsConstructor
@Slf4j
public class TspInformationProvider {

    private final List<TspService> tspServices;
    private final String productType;

    /**
     * Verify AKI (authority key identifier - an X.509 v3 certificate extension - derived from the public key of the given issuer certificate) must match with
     * SKI (subject key identifier - an X.509 v3 certificate extension - derived from the public key of the given end-entity certificate).
     *
     * @param x509EeCert     end-entity certificate
     * @param x509IssuerCert issuer certificate determined from TSL file
     * @return true when aki matches ski otherwise false
     */
    private static boolean verifyAkiMatchesSki(@NonNull final X509Certificate x509EeCert,
        @NonNull final X509Certificate x509IssuerCert) {
        final byte[] subjectKeyIdentifier = x509IssuerCert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        final Optional<ASN1OctetString> skiAsOctet = Optional
            .ofNullable(ASN1OctetString.getInstance(subjectKeyIdentifier));
        if (skiAsOctet.isEmpty()) {
            log.debug("Extension SUBJECT_KEY_IDENTIFIER_OID: {} konnte in {} nicht gefunden werden.",
                Extension.subjectKeyIdentifier.getId(),
                x509EeCert.getSubjectX500Principal());
            return false;
        }
        final SubjectKeyIdentifier subKeyIdentifier = SubjectKeyIdentifier.getInstance(skiAsOctet.get().getOctets());

        final byte[] authorityKeyIdentifier = x509EeCert
            .getExtensionValue(Extension.authorityKeyIdentifier.getId());
        final Optional<ASN1OctetString> akiAsOctet = Optional
            .ofNullable(ASN1OctetString.getInstance(authorityKeyIdentifier));
        if (akiAsOctet.isEmpty()) {
            log.debug("Extension AUTHORITY_KEY_IDENTIFIER_OID: {} konnte in {} nicht gefunden werden.",
                Extension.authorityKeyIdentifier.getId(),
                x509EeCert.getSubjectX500Principal());
            return false;
        }
        final ASN1Primitive akiSequenceAsOctet;
        try {
            akiSequenceAsOctet = ASN1Primitive.fromByteArray(akiAsOctet.get().getOctets());
        } catch (final IOException e) {
            log.debug("Octets des AUTHORITY_KEY_IDENTIFIER konnten in {} nicht gefunden werden.",
                x509EeCert.getSubjectX500Principal());
            log.trace(e.toString());
            return false;
        }
        final AuthorityKeyIdentifier authKeyIdentifier = AuthorityKeyIdentifier.getInstance(akiSequenceAsOctet);
        return Arrays.equals(subKeyIdentifier.getKeyIdentifier(), authKeyIdentifier.getKeyIdentifier());
    }

    /**
     * Get timestamp of status change of given TspService from TSL file.
     *
     * @param issuerTspService TspService from TSL file
     * @return ZonedDateTime timestamp of status change
     */
    private static ZonedDateTime getCertificateAuthorityStatusStartingTime(@NonNull final TspService issuerTspService) {
        return issuerTspService.getTspServiceType().getServiceInformation().getStatusStartingTime()
            .toGregorianCalendar()
            .toZonedDateTime();
    }

    /**
     * Compose an information subset of a TspService if one of its issuers signed the given end-entity certificate.
     *
     * @param x509EeCert The end-entity certificate
     * @return information subset of a TspService {@link TspServiceSubset}
     * @throws GemPkiException exception thrown if certificate cannot be found
     */
    public TspServiceSubset getTspServiceSubset(@NonNull final X509Certificate x509EeCert) throws GemPkiException {
        Optional<X509Certificate> foundX509IssuerCert = Optional.empty();

        for (final TspService tspService : tspServices) {
            try {
                for (final DigitalIdentityType dit : tspService.getTspServiceType().getServiceInformation()
                    .getServiceDigitalIdentity()
                    .getDigitalId()) {
                    final X509Certificate x509IssuerCert = getX509CertificateFromByteArray(dit.getX509Certificate());
                    if (x509EeCert.getIssuerX500Principal().equals(x509IssuerCert.getSubjectX500Principal())) {
                        if (verifyAkiMatchesSki(x509EeCert, x509IssuerCert)) {
                            return TspServiceSubset.builder()
                                .x509IssuerCert(x509IssuerCert)
                                .serviceStatus(tspService.getTspServiceType().getServiceInformation().getServiceStatus())
                                .statusStartingTime(getCertificateAuthorityStatusStartingTime(tspService))
                                .serviceSupplyPoint(getFirstServiceSupplyPointFromTspService(tspService))
                                .extensions(tspService.getTspServiceType().getServiceInformation()
                                    .getServiceInformationExtensions().getExtension()).build();
                        }
                        foundX509IssuerCert = Optional.of(x509IssuerCert);
                    }

                }
            } catch (final NullPointerException e) {
                log.debug("skipped {} due to missing tsp information",
                    tspService.getTspServiceType().getServiceInformation().getServiceName().getName().get(0).getValue());
            }
        }

        if (foundX509IssuerCert.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1027);
        } else {
            throw new GemPkiException(productType, ErrorCode.SE_1023);
        }
    }

    /**
     * Get a certificate from a given byte array.
     *
     * @param bytes certificate as byte array
     * @return X509Certificate
     * @throws GemPkiException exception thrown if certificate cannot be extracted
     */
    private X509Certificate getX509CertificateFromByteArray(final byte[] bytes) throws GemPkiException {
        try (final InputStream in = new ByteArrayInputStream(bytes)) {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(in);
        } catch (final CertificateException | IOException e) {
            throw new GemPkiException(productType, ErrorCode.TE_1002, e);
        }
    }

    /**
     * Get OCSP responder URL from given TspService.
     *
     * @param tspService the given TspService
     * @return ServiceSupplyPoint as string (URL)
     * @throws GemPkiException exception thrown if service supply point is missing
     */
    private String getFirstServiceSupplyPointFromTspService(final TspService tspService)
        throws GemPkiException {
        final Optional<ServiceSupplyPointsType> serviceSupplyPointsType = Optional
            .ofNullable(tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints());
        if (serviceSupplyPointsType.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1026);
        }
        final String firstServiceSupplyPoint = serviceSupplyPointsType.get().getServiceSupplyPoint().get(0).getValue();
        if (firstServiceSupplyPoint.isBlank()) {
            throw new GemPkiException(productType, ErrorCode.TE_1026);
        } else {
            log.debug("Der erste ServiceSupplyPoint wurde ermittelt {}", firstServiceSupplyPoint);
            return firstServiceSupplyPoint;
        }
    }
}
