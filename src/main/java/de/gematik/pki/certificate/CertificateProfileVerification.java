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
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Node;

/**
 * Class for verification checks on a certificate against a profile. This class works with parameterized variables (defined by builder pattern) and with given
 * variables provided by runtime (method parameters).
 */

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class CertificateProfileVerification {

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;
    @NonNull
    private final CertificateProfile certificateProfile;
    @NonNull
    private final X509Certificate x509EeCert;

    // ####################  Start KeyUsage ########################################################

    /**
     * Verify that all intended KeyUsage bit(s) of certificate profile {@link CertificateProfile} match against KeyUsage(s) of parameterized end-entity
     * certificate.
     *
     * @throws GemPkiException if the certificate has a wrong key usage
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
    private static List<KeyUsage> getIntendedKeyUsagesFromCertificateProfile(final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getKeyUsages();
    }

    // ####################  End KeyUsage ########################################################

    // ####################  Start ExtendedKeyUsage ##############################################

    /**
     * Verify oid of intended ExtendedKeyUsage(s) from certificate profile {@link CertificateProfile} must match with oid(s) from a parameterized end-entity
     * certificate with respect to cardinality.
     *
     * @throws GemPkiException if certificate has a wrong key usage
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
    private static List<String> getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages()
            .stream().map(ExtendedKeyUsage::getOid).collect(Collectors.toList());
    }
    // ####################  End ExtendedKeyUsage ########################################################

    // ############## Start certificate type checks ######################################################

    /**
     * Verify type of parameterized end-entity certificate against parameterized certificate profile {@link CertificateProfile}.
     *
     * @throws GemPkiException if certificate type verification fails
     */
    public void verifyCertificateType() throws GemPkiException {
        final Set<String> certificatePolicyOids = getCertificatePolicyOids(x509EeCert);
        verifyCertificateProfileByCertificateTypeOid(certificatePolicyOids);
        verifyCertificateTypeOidInIssuerTspServiceExtension(certificatePolicyOids);
    }

    /**
     * Check given list of certificate policy type oid(s) contains type oid from parameterized certificate profile {@link CertificateProfile}.
     *
     * @param certificatePolicyOidList list with policy oid(s)
     * @throws GemPkiException if the certificate has a wong cert type
     */
    private void verifyCertificateProfileByCertificateTypeOid(final Set<String> certificatePolicyOidList)
        throws GemPkiException {
        if (!certificatePolicyOidList.contains(certificateProfile.getCertificateType().getOid())) {
            log.debug("ZertifikatsTypOids im Zertifikat: {}", certificatePolicyOidList);
            log.debug("Erwartete ZertifikatsTypOid: {}", certificateProfile.getCertificateType().getOid());
            throw new GemPkiException(productType, ErrorCode.SE_1018);
        }
    }

    /**
     * Verify that list of extension oid(s) from issuer TspService contains at least one oid of given certificate type oid list.
     *
     * @param certificateTypeOidList a list with certificate type oid(s)
     * @throws GemPkiException if the certificate issuer is not allowed to issue this cert type
     */
    private void verifyCertificateTypeOidInIssuerTspServiceExtension(final Set<String> certificateTypeOidList)
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
     * Get policy oids to given end-entity certificate. 1.Test: exists policy extension oid identifier at all (implizit over IllegalArgumentException). 2.Test:
     * extract value from policy extension oid.
     *
     * @param x509EeCert end-entity certificate
     * @return Set<String> policy oids from end-entity certificate
     * @throws GemPkiException if the certificate has no cert type
     */
    private Set<String> getCertificatePolicyOids(final X509Certificate x509EeCert) throws GemPkiException {
        try {
            final Policies policies = new Policies(x509EeCert);
            if (policies.getPolicyOids().isEmpty()) {
                throw new GemPkiException(productType, ErrorCode.SE_1033);
            }
            return policies.getPolicyOids();
        } catch (final IllegalArgumentException e) {
            throw new GemPkiException(productType, ErrorCode.SE_1033);
        } catch (final CertificateEncodingException | IOException e) {
            throw new GemPkiException(productType, ErrorCode.TE_1019); //difficult to reach
        }
    }
    // ############## End certificate type checks #######################################################

}
