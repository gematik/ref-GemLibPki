package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

@Slf4j
@RequiredArgsConstructor
public class IssuerServiceStatusValidator implements CertificateValidator {

    @NonNull
    private final String productType;
    @NonNull
    private final TspServiceSubset tspServiceSubset;

    /**
     * Verify issuer service status from tsl file. The status determines if an end-entity certificate
     * was issued after the CA (Issuer) was revoked.
     *
     * @throws GemPkiException if certificate has been revoked
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull  ZonedDateTime referenceDate, @NonNull ValidationContext context) throws GemPkiException {

        if (!tspServiceSubset.getServiceStatus().equals(TslConstants.SVCSTATUS_REVOKED)) {
            return;
        }

        final ZonedDateTime statusStartingTime = tspServiceSubset.getStatusStartingTime();
        final ZonedDateTime notBefore = x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);

        if (statusStartingTime.isBefore(notBefore)) {
            throw new GemPkiException(productType, ErrorCode.SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL);
        }
    }
}
