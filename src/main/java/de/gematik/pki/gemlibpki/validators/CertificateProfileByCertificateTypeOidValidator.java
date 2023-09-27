package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.certificate.Policies;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;

@Slf4j
@RequiredArgsConstructor
public class CertificateProfileByCertificateTypeOidValidator implements CertificateProfileValidator {

    @NonNull
    private final String productType;

    /**
     * Check given list of certificate policy type oid(s) contains type oid from parameterized
     * certificate profile {@link CertificateProfile}.
     *
     * @throws GemPkiException if the certificate has a wong cert type
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile) throws GemPkiException {
        if (certificateProfile.equals(CERT_PROFILE_C_TSL_SIG)) {
            return;
        }
        final Set<String> certificatePolicyOidList = getCertificatePolicyOids(x509EeCert);

        if (certificateProfile.getCertificateType().equals(CertificateType.CERT_TYPE_ANY)) {
            log.info(
                    "Skipping check of CertificateTypeOid, because of user request. CertProfile used: {}",
                    certificateProfile.name());
            return;
        }

        if (!certificatePolicyOidList.contains(certificateProfile.getCertificateType().getOid())) {
            log.debug("ZertifikatsTypOids im Zertifikat: {}", certificatePolicyOidList);
            log.debug(
                    "Erwartete ZertifikatsTypOid: {}", certificateProfile.getCertificateType().getOid());
            throw new GemPkiException(productType, ErrorCode.SE_1018_CERT_TYPE_MISMATCH);
        }
    }

    /**
     * Get policy oids to given end-entity certificate. 1.Test: exists policy extension oid identifier
     * at all (implizit over IllegalArgumentException). 2.Test: extract value from policy extension
     * oid.
     *
     * @param x509EeCert end-entity certificate
     * @return Set<String> policy oids from end-entity certificate
     * @throws GemPkiException if the certificate has no cert type
     */
    private Set<String> getCertificatePolicyOids(final X509Certificate x509EeCert)
            throws GemPkiException {
        try {
            final Policies policies = new Policies(x509EeCert);
            if (policies.getPolicyOids().isEmpty()) {
                throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
            }
            return policies.getPolicyOids();
        } catch (final IllegalArgumentException e) {
            throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
        } catch (final IOException e) {
            throw new GemPkiException(productType, ErrorCode.TE_1019_CERT_READ_ERROR);
        }
    }
}
