package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class ExtendedKeyUsageValidator implements CertificateProfileValidator {

    @NonNull
    private final String productType;

    /**
     * Verify oid of intended ExtendedKeyUsage(s) from certificate profile {@link CertificateProfile}
     * must match with oid(s) from a parameterized end-entity certificate with respect to cardinality.
     *
     * @throws GemPkiException if certificate has a wrong key usage
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile) throws GemPkiException {

        final List<String> intendedExtendedKeyUsageOidList =
                getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);

        if (intendedExtendedKeyUsageOidList.isEmpty() || !certificateProfile.isFailOnMissingEku()) {
            log.info(
                    "Skipping check of extendedKeyUsage, because of user request. CertProfile used: {}",
                    certificateProfile.name());
            return;
        }

        final List<String> eeExtendedKeyUsagesOid;
        try {
            eeExtendedKeyUsagesOid = x509EeCert.getExtendedKeyUsage();
        } catch (final CertificateParsingException e) {
            throw new GemPkiRuntimeException(
                    "Fehler beim Lesen der ExtendedKeyUsages des Zertifikats: "
                            + x509EeCert.getSubjectX500Principal().getName(),
                    e);
        }

        if (eeExtendedKeyUsagesOid == null) {
            throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
        }
        final List<String> filteredList =
                eeExtendedKeyUsagesOid.stream()
                        .filter(
                                eeOid ->
                                        intendedExtendedKeyUsageOidList.stream()
                                                .anyMatch(intOid -> intOid.equals(eeOid)))
                        .toList();
        if (filteredList.isEmpty()
                || (eeExtendedKeyUsagesOid.size() != intendedExtendedKeyUsageOidList.size())) {
            log.debug("{}", ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
            throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
        }
    }

    /**
     * Get list of oid(s) of ExtendedKeyUsage(s) to the parameterized profile.
     *
     * @param certificateProfile The certificate profile
     * @return List of oid(s) of ExtendedKeyUsages from certificate profile {@link CertificateProfile}
     */
    private static List<String> getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(
            final CertificateProfile certificateProfile) {
        return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages().stream()
                .map(ExtendedKeyUsage::getOid)
                .toList();
    }


}
