package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

@Slf4j
@RequiredArgsConstructor
public class ValidityValidator implements CertificateValidator {

    @NonNull
    private final String productType;

    /**
     * Verify validity period of parameterized end-entity certificate against a given reference date.
     * TUC_PKI_002 „Gültigkeitsprüfung des Zertifikats“
     *
     * @param referenceDate date to check against
     * @throws GemPkiException if certificate is not valid in time
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate, @NonNull ValidationContext context) throws GemPkiException {

        boolean isValid = isBetween(
                        referenceDate,
                        x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC),
                        x509EeCert.getNotAfter().toInstant().atZone(ZoneOffset.UTC));

        if (!isValid) {
            log.debug(
                    "Das Referenzdatum {} liegt nicht innerhalb des Gültigkeitsbereichs des Zertifikates.",
                    referenceDate);
            throw new GemPkiException(productType, ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME);
        }
    }

    private boolean isBetween(
            final ZonedDateTime referenceDate,
            final ZonedDateTime startDate,
            final ZonedDateTime endDate) {
        return referenceDate.isAfter(startDate) && referenceDate.isBefore(endDate);
    }
}
