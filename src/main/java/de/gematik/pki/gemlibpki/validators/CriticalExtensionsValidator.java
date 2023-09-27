package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeSet;

@Slf4j
@RequiredArgsConstructor
public class CriticalExtensionsValidator implements CertificateProfileValidator {

    @NonNull
    private final String productType;

    /**
     * AFO GS-A_4661-01 (RFC5280#4.2)
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile) throws GemPkiException {

        final Set<String> certCriticalExtensions = x509EeCert.getCriticalExtensionOIDs();

        // NOTE: as specified in gemSpec_PKI 2.15.0 for all certificate profiles in Kapitel 5
        // X.509-Zertifikate

        final Set<String> expectedCriticalExtensions =
                Set.of(Extension.basicConstraints.getId(), Extension.keyUsage.getId());

        if (!expectedCriticalExtensions.equals(certCriticalExtensions)) {
            log.error(
                    "Detected unknown / missing critical extensions in certificate {} vs expected {}",
                    new TreeSet<>(certCriticalExtensions),
                    new TreeSet<>(expectedCriticalExtensions));
            throw new GemPkiException(productType, ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION);
        }
    }
}
