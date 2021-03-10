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
import de.gematik.pki.tsl.TspServiceSubset;
import eu.europa.esig.jaxb.tsl.ExtensionType;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.w3c.dom.Node;

/**
 * Class to verify a certificate against a profile. This class works with parameterized variables (defined by builder
 * pattern) and with given variables provided by runtime (method parameters).
 */

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class CertificateVerification {

    public static final String SVCSTATUS_REVOKED = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked";

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;
    @NonNull
    private final CertificateProfile certificateProfile;
    @NonNull
    private final X509Certificate x509EeCert;

    public void verifyValidity() throws GemPkiException {
        verifyValidity(ZonedDateTime.now());
    }

    /**
     * Verify validity period of parameterized end-entity certificate against a given reference date.
     *
     * @param referenceDate date to check against
     * @throws GemPkiException
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
     * Verify signature of parameterized end-entity certificate against given issuer certificate. Issuer certificate
     * (CA) is determined from TSL file.
     *
     * @param x509IssuerCert issuer certificate
     * @throws GemPkiException
     */
    public void verifySignature(@NonNull final X509Certificate x509IssuerCert) throws GemPkiException {
        try {
            x509EeCert.verify(x509IssuerCert.getPublicKey());
            log.debug("Signaturprüfung von {} erfolgreich", x509EeCert.getSubjectX500Principal());
        } catch (final GeneralSecurityException verifyFailed) {
            throw new GemPkiException(productType, ErrorCode.SE_1024, verifyFailed); //CERTIFICATE_NOT_VALID_MATH
        }
    }

    // ####################  Start KeyUsage ########################################################

    /**
     * Verify that all intended KeyUsage bit(s) of certificate profile {@link CertificateProfile} match against
     * KeyUsage(s) of parameterized end-entity certificate.
     *
     * @throws GemPkiException
     */
    public void verifyKeyUsage() throws GemPkiException {

        if (x509EeCert.getKeyUsage() == null) {
            throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE
        }

        int nrBitsEe = 0;
        for (final boolean b : x509EeCert.getKeyUsage()) {
            if (b) {
                nrBitsEe++;
            }
        }

        final List<KeyUsage> intendedKeyUsageList =
            getIntendedKeyUsagesFromCertificateProfile(certificateProfile);

        if (nrBitsEe != intendedKeyUsageList.size()) {
            throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE

        }

        for (final KeyUsage ku : intendedKeyUsageList) {
            if (!x509EeCert.getKeyUsage()[ku.getBit()]) {
                throw new GemPkiException(productType, ErrorCode.SE_1016); //WRONG_KEY_USAGE
            }
        }
    }

    /**
     * Get list of KeyUsage(s) to the parameterized certificate profile {@link CertificateProfile}.
     *
     * @param certificateProfile The certificate profile
     * @return List with keyUsage(s)
     */
    private List<KeyUsage> getIntendedKeyUsagesFromCertificateProfile(
        @NonNull final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getKeyUsages();
    }

    // ####################  End KeyUsage ########################################################

    // ####################  Start ExtendedKeyUsage ##############################################

    /**
     * Verify oid of intended ExtendedKeyUsage(s) from certificate profile {@link CertificateProfile} must match with
     * oid(s) from a parameterized end-entity certificate with respect to cardinality.
     *
     * @throws GemPkiException
     */
    public void verifyExtendedKeyUsage() throws GemPkiException {
        final List<String> eeExtendedKeyUsagesOid;
        try {
            eeExtendedKeyUsagesOid = x509EeCert.getExtendedKeyUsage();
        } catch (final CertificateParsingException e) {
            throw new GemPkiException(productType, ErrorCode.CERTIFICATE_READ, e);
        }

        final List<String> intendedExtendedKeyUsageOidList = getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(
            certificateProfile);

        if (eeExtendedKeyUsagesOid == null) {
            if (intendedExtendedKeyUsageOidList.isEmpty() || !certificateProfile.isFailOnMissingEku()) {
                return;
            } else {
                throw new GemPkiException(productType, ErrorCode.SE_1017);
            }
        }

        final List<String> filteredList = eeExtendedKeyUsagesOid.stream()
            .filter(eeOid -> intendedExtendedKeyUsageOidList.stream().anyMatch(intOid -> intOid.equals(eeOid)))
            .collect(Collectors.toList());

        if (filteredList.isEmpty() || eeExtendedKeyUsagesOid.size() != intendedExtendedKeyUsageOidList.size()) {
            log.debug(ErrorCode.SE_1017.getErrorMessage(productType));
            throw new GemPkiException(productType, ErrorCode.SE_1017);
        }
    }

    /**
     * Get list of oid(s) of ExtendedKeyUsage(s) to the parameterized profile.
     *
     * @param certificateProfile The certificate profile
     * @return List of oid(s) of ExtendedKeyUsages from certificate profile {@link CertificateProfile}
     */
    private List<String> getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(
        @NonNull final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages()
            .stream().map(ExtendedKeyUsage::getOid).collect(Collectors.toList());
    }

    // ####################  End ExtendedKeyUsage ########################################################

    // ####################  Start issuer checks #########################################################

    /**
     * Verify issuer service status from tsl file. The status determines if an end-entity certificate was issued after
     * the CA (Issuer) was revoked.
     *
     * @throws GemPkiException
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

    // ####################  Start certificate status checks ##########################################

    // ####################  End certificate status checks ################################################

    // ############## Start Certificate type checks #######################################################

    /**
     * Verify type of parameterized end-entity certificate against parameterized certificate profile {@link
     * CertificateProfile}.
     *
     * @throws GemPkiException
     */
    public void verifyCertificateType() throws GemPkiException {
        final byte[] certificatePoliciesExtension = getCertificatePoliciesExtension(x509EeCert);
        final List<String> certificatePolicyOids = extractPolicyOids(certificatePoliciesExtension);
        verifyCertificateProfileByCertificateTypeOid(certificatePolicyOids);
        verifyCertificateTypeOidInIssuerTspServiceExtension(certificatePolicyOids);
    }

    /**
     * Check given list of certificate policy type oid(s) contains type oid from parameterized certificate profile
     * {@link CertificateProfile}.
     *
     * @param certificatePolicyOidList list with policy oid(s)
     * @throws GemPkiException
     */
    private void verifyCertificateProfileByCertificateTypeOid(@NonNull final List<String> certificatePolicyOidList)
        throws GemPkiException {
        if (!certificatePolicyOidList.contains(certificateProfile.getCertificateType().getOid())) {
            throw new GemPkiException(productType, ErrorCode.SE_1018);
        }
    }

    /**
     * Verify that list of extension oid(s) from issuer TspService contains at least one oid of given certificate type
     * oid list.
     *
     * @param certificateTypeOidList a list with certificate type oid(s)
     * @throws GemPkiException
     */
    private void verifyCertificateTypeOidInIssuerTspServiceExtension(@NonNull final List<String> certificateTypeOidList)
        throws GemPkiException {
        log.debug("Prüfe CA Authorisierung für die Herausgabe des Zertifikatstyps {} ",
            certificateProfile.getCertificateType().getOidReference());
        for (final ExtensionType extensionType : tspServiceSubset.getExtensions()) {
            final List<Object> content = extensionType.getContent();
            for (final Object object : content) {
                if (object instanceof Node) {
                    final String node = ((Node) object).getFirstChild().getNodeValue();
                    if (certificateTypeOidList.contains(node.trim())) {
                        return;
                    }
                }
            }
        }
        throw new GemPkiException(productType, ErrorCode.SE_1061);
    }

    /**
     * Get policy extension to given end-entity certificate. 1.Test: exists policy extension oid identifier at all,
     * 2.Test: extract value from policy extension oid
     *
     * @param x509EeCert end-entity certificate
     * @return byte[] policy extensions from end-entity certificate
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

    /**
     * Extract policy extension from given byte array. The oid "1.2.276.0.76.4.163" is not relevant according to gematik
     * spec and therefore sorted out.
     *
     * @param certificatePolicyExtension the policy extension as byte array
     * @return List<String> the extracted oid(s)
     */
    private List<String> extractPolicyOids(@NonNull final byte[] certificatePolicyExtension) {
        final String filterOutNotDesiredPolicyOid = "1.2.276.0.76.4.163";
        return (List<String>) Collections.list(
            ASN1Sequence
                .getInstance(Arrays.copyOfRange(certificatePolicyExtension, 2, certificatePolicyExtension.length))
                .getObjects()).stream()
            .filter(DLSequence.class::isInstance)
            .map(sequence -> ((DLSequence) sequence).getObjects())
            .flatMap(enumeration -> Collections.list((Enumeration) enumeration).stream())
            .map(Object::toString)
            .filter(oid -> !filterOutNotDesiredPolicyOid.equals(oid))
            .collect(Collectors.toList());
    }

    // ############## End Certificate type checks #######################################################

}
