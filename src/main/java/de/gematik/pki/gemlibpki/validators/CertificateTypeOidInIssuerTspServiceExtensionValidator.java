package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.Policies;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Node;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;

@Slf4j
@RequiredArgsConstructor
public class CertificateTypeOidInIssuerTspServiceExtensionValidator implements CertificateProfileValidator {

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;

    /**
     * Verify that list of extension oid(s) from issuer TspService contains at least one oid of given
     * certificate type oid list.
     *
     * @throws GemPkiException if the certificate issuer is not allowed to issue this cert type
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile) throws GemPkiException {
        if (certificateProfile.equals(CERT_PROFILE_C_TSL_SIG)) {
            return;
        }
        final Set<String> certificateTypeOidList = getCertificatePolicyOids(x509EeCert);

        log.debug(
                "Prüfe CA Autorisierung für die Herausgabe des Zertifikatstyps {} ",
                certificateProfile.getCertificateType().getOidReference());
        for (final ExtensionType extensionType : tspServiceSubset.getExtensions()) {
            final List<Object> content = extensionType.getContent();
            for (final Object object : content) {
                if (object instanceof final Node node) {
                    final Node firstChild = node.getFirstChild();
                    if (certificateTypeOidList.contains(firstChild.getNodeValue().trim())) {
                        return;
                    }
                }
            }
        }
        throw new GemPkiException(productType, ErrorCode.SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED);
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
