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
import de.gematik.pki.tsl.TspService;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.ExtensionType;
import eu.europa.esig.jaxb.tsl.ServiceSupplyPointsType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.w3c.dom.Node;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class CertificateVerification {

    public static final String SVCSTATUS_REVOKED = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked";

    @NonNull
    private final String productType;
    @NonNull
    private final List<TspService> tspServiceList;
    @NonNull
    private final CertificateProfile certificateProfile;
    @NonNull
    private final X509Certificate x509EeCert;

    public void verifyValidity() throws GemPkiException {
        verifyValidity(ZonedDateTime.now());
    }

    public void verifyValidity(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {

        if (!(x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC).isBefore(referenceDate) &&
            x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC)
                .isAfter(referenceDate))) {
            log.debug(
                "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitsbereichs des Zertifikates.", referenceDate);
            throw new GemPkiException(productType, ErrorCode.SE_1021); //CERTIFICATE_NOT_VALID_TIME
        }
    }

    public void verifySignature(@NonNull final X509Certificate issuer) throws GemPkiException {
        try {
            x509EeCert.verify(issuer.getPublicKey());
            log.debug("Signaturprüfung von {} erfolgreich", x509EeCert.getSubjectX500Principal());
        } catch (final GeneralSecurityException verifyFailed) {
            throw new GemPkiException(productType, ErrorCode.SE_1024, verifyFailed); //CERTIFICATE_NOT_VALID_MATH
        }
    }

    // ####################  Start KeyUsage ########################################################

    public void verifyKeyUsage() throws GemPkiException {
        final List<KeyUsage> intendedKeyUsageList =
            getIntendedKeyUsagesFromCertificateProfile(certificateProfile);

        if (x509EeCert.getKeyUsage() == null) {
            throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE
        }

        int nrBitsEe = 0;
        for (final boolean b : x509EeCert.getKeyUsage()) {
            if (b) {
                nrBitsEe++;
            }
        }
        if (nrBitsEe != intendedKeyUsageList.size()) {
            throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE

        }

        for (final KeyUsage ku : intendedKeyUsageList) {
            if (!x509EeCert.getKeyUsage()[ku.getBit()]) {
                throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE
            }
        }
    }

    private List<KeyUsage> getIntendedKeyUsagesFromCertificateProfile(
        @NonNull final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getKeyUsages();
    }

    // ####################  End KeyUsage ########################################################

    // ####################  Start ExtendedKeyUsage ##############################################

    public void verifyExtendedKeyUsage() throws GemPkiException {
        final List<String> eeExtendedKeyUsages;
        try {
            eeExtendedKeyUsages = x509EeCert.getExtendedKeyUsage();
        } catch (final CertificateParsingException e) {
            throw new GemPkiException(productType, ErrorCode.CERTIFICATE_READ, e);
        }

        final List<String> intendedExtendedKeyUsageList = getIntendedExtendedKeyUsagesFromCertificateProfile(
            certificateProfile);

        if (eeExtendedKeyUsages == null) {
            if (intendedExtendedKeyUsageList.isEmpty() || !certificateProfile.isFailOnMissingEku()) {
                return;
            } else {
                throw new GemPkiException(productType, ErrorCode.SE_1017);
            }
        }

        final List<String> filteredList = eeExtendedKeyUsages.stream()
            .filter(l1 -> intendedExtendedKeyUsageList.stream().anyMatch(l2 -> l2.equals(l1)))
            .collect(Collectors.toList());

        if (filteredList.isEmpty() || eeExtendedKeyUsages.size() != intendedExtendedKeyUsageList.size()) {
            log.debug(ErrorCode.SE_1017.getErrorMessage(productType));
            throw new GemPkiException(productType, ErrorCode.SE_1017);
        }
    }

    private List<String> getIntendedExtendedKeyUsagesFromCertificateProfile(
        @NonNull final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages()
            .stream().map(ExtendedKeyUsage::getOid).collect(Collectors.toList());
    }

    // ####################  End ExtendedKeyUsage ########################################################

    // ####################  Start issuer checks #########################################################

    public void verifyIssuerServiceStatus() throws GemPkiException {
        final TspService issuerServiceType = getIssuerTspService();

        log.debug("Bei der Prüfung des Aussteller Service Status wurde der Aussteller ServiceTyp zu {} ermittelt.",
            issuerServiceType.getTspServiceType().getServiceInformation().getServiceTypeIdentifier());
        final String serviceStatus = getCertificateAuthorityServiceStatus(issuerServiceType);
        if (serviceStatus.equals(SVCSTATUS_REVOKED)) {
            final ZonedDateTime statusStartingTime = getCertificateAuthorityStatusStartingTime(issuerServiceType);
            if (statusStartingTime.isBefore(x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC))) {
                throw new GemPkiException(productType, ErrorCode.SE_1036);
            }
        }
    }

    public TspService getIssuerTspService() throws GemPkiException {
        Optional<X509Certificate> foundIssuerCert = Optional.empty();

        for (final TspService tspService : tspServiceList) {
            for (final DigitalIdentityType dit : tspService.getTspServiceType().getServiceInformation()
                .getServiceDigitalIdentity()
                .getDigitalId()) {
                final X509Certificate issuerCert = getX509CertificateFromByteArray(dit.getX509Certificate());
                if (x509EeCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                    foundIssuerCert = Optional.of(issuerCert);
                    if (verifyAkiMatchesSki(issuerCert)) {
                        return tspService;
                    }
                }
            }
        }

        if (foundIssuerCert.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1027);
        } else {
            throw new GemPkiException(productType, ErrorCode.SE_1023);
        }
    }

    private boolean verifyAkiMatchesSki(@NonNull final X509Certificate issuerX509Cert) {
        final byte[] subjectKeyIdentifier = issuerX509Cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
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
     * Reads ServiceStatus of given Certificate Authority certificate.
     *
     * @param tspService
     * @return ServiceStatus URI as String
     */
    private String getCertificateAuthorityServiceStatus(@NonNull final TspService tspService) {
        return tspService.getTspServiceType().getServiceInformation().getServiceStatus();
    }

    private ZonedDateTime getCertificateAuthorityStatusStartingTime(@NonNull final TspService issuerTspService) {
        return issuerTspService.getTspServiceType().getServiceInformation().getStatusStartingTime()
            .toGregorianCalendar()
            .toZonedDateTime();
    }

    // ####################  End issuer checks ########################################################

    // ####################  Start certificate status checks ##########################################

    public String getServiceSupplyPointFromEeCertificate() throws GemPkiException {
        return getFirstServiceSupplyPointFromTspService(getIssuerTspService());
    }

    public String getFirstServiceSupplyPointFromTspService(final TspService tspService)
        throws GemPkiException {
        final Optional<ServiceSupplyPointsType> serviceSupplyPointsType = Optional
            .ofNullable(tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints());
        if (serviceSupplyPointsType.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1026);
        }
        final List<String> serviceSupplyPoints = serviceSupplyPointsType.get().getServiceSupplyPoint();
        if (serviceSupplyPoints.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1026);
        } else {
            log.debug("Der erste ServiceSupplyPoint wurde ermittelt {}", serviceSupplyPoints.get(0));
            return serviceSupplyPoints.get(0);
        }
    }

    // ####################  End certificate status checks ################################################

    // ############## Start Certificate type checks #######################################################

    public void verifyCertificateType() throws GemPkiException {
        final byte[] certificatePoliciesExtension = getCertificatePoliciesExtension(x509EeCert);
        final List<String> certificatePolicyOids = extractPolicyOids(certificatePoliciesExtension);
        verifyCertificateProfileByCertificateTypeOid(certificatePolicyOids);
        verifyCertificateTypeOidInIssuerTspServiceExtension(certificatePolicyOids);
    }

    /**
     * Checks existing certificate oid against intended certificate type.
     *
     * @param certificatePolicyOids
     * @throws GemPkiException
     */
    private void verifyCertificateProfileByCertificateTypeOid(@NonNull final List<String> certificatePolicyOids)
        throws GemPkiException {
        if (!certificatePolicyOids.contains(certificateProfile.getCertificateType().getOid())) {
            throw new GemPkiException(productType, ErrorCode.SE_1018);
        }
    }

    private void verifyCertificateTypeOidInIssuerTspServiceExtension(@NonNull final List<String> certificateTypeOids)
        throws GemPkiException {
        log.debug("Prüfe CA Authorisierung für die Herausgabe des Zertifikatstyps {} ",
            certificateProfile.getCertificateType().getOidReference());
        final List<ExtensionType> extensionTypList = new ArrayList<>(
            getIssuerTspService().getTspServiceType().getServiceInformation()
                .getServiceInformationExtensions().getExtension());
        for (final ExtensionType extensionType : extensionTypList) {
            final List<Object> content = extensionType.getContent();
            for (final Object object : content) {
                if (object instanceof Node) {
                    final String node = ((Node) object).getFirstChild().getNodeValue();
                    if (certificateTypeOids.contains(node.trim())) {
                        return;
                    }
                }
            }
        }
        throw new GemPkiException(productType, ErrorCode.SE_1061);
    }

    /**
     * Ermitteln der Policy Extensions aus dem Zertifikat. 1. Test: existiert die Policy Extension OID 2. Test:
     * extrahieren des Wertes aus der Policy Extension OID
     *
     * @param x509EeCert das zu prüfende X509 Zertifikat
     * @return byte[] Policy Extensions aus dem Zertifikat
     * @throws GemPkiException
     */
    private byte[] getCertificatePoliciesExtension(@NonNull final X509Certificate x509EeCert) throws GemPkiException {
        final Optional<byte[]> certificatePoliciesExtension = Optional
            .ofNullable(x509EeCert.getExtensionValue(Extension.certificatePolicies.getId()));
        if (certificatePoliciesExtension.isEmpty() || certificatePoliciesExtension.get().length == 0) {
            throw new GemPkiException(productType, ErrorCode.SE_1033);
        }
        final Optional<List<String>> extractPolicyOidsList = Optional
            .ofNullable(extractPolicyOids(certificatePoliciesExtension.get()));
        if (extractPolicyOidsList.isEmpty() || extractPolicyOidsList.get().isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.SE_1033);
        }
        return certificatePoliciesExtension.get();
    }

    private List<String> extractPolicyOids(@NonNull final byte[] certificatePoliciesExtension) {
        final String filterOutNotDesiredPolicyOid = "1.2.276.0.76.4.163";
        return (List<String>) Collections.list(
            ASN1Sequence
                .getInstance(Arrays.copyOfRange(certificatePoliciesExtension, 2, certificatePoliciesExtension.length))
                .getObjects()).stream()
            .filter(DLSequence.class::isInstance)
            .map(sequence -> ((DLSequence) sequence).getObjects())
            .flatMap(enumeration -> Collections.list((Enumeration) enumeration).stream())
            .map(Object::toString)
            .filter(oid -> !filterOutNotDesiredPolicyOid.equals(oid))
            .collect(Collectors.toList());
    }

    // ############## End Certificate type checks #######################################################

    // ############## Start Utils stuff #################################################################

    private X509Certificate getFirstTSPServiceCertificate(@NonNull final TspService tspServiceType)
        throws GemPkiException {
        final List<DigitalIdentityType> diTypes = tspServiceType.getTspServiceType().getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId();
        if (diTypes.isEmpty()) {
            throw new GemPkiException(productType, ErrorCode.TE_1027);
        } else {
            final X509Certificate x509Cert = getX509CertificateFromByteArray(diTypes.get(0).getX509Certificate());
            log.debug("Für den übergebenen TSPService wurde das erste Zertifikat mit Common Name {} ermittelt",
                x509Cert.getSubjectX500Principal().getName());
            return x509Cert;
        }
    }

    public X509Certificate getIssuerCertificate() throws GemPkiException {
        return getFirstTSPServiceCertificate(getIssuerTspService());
    }


    private X509Certificate getX509CertificateFromByteArray(@NonNull final byte[] bytes) throws GemPkiException {
        try (final InputStream in = new ByteArrayInputStream(bytes)) {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(in);
        } catch (final CertificateException | IOException e) {
            throw new GemPkiException(productType, ErrorCode.TE_1002, e);
        }
    }

    // ############## End Utils stuff #################################################################
}
