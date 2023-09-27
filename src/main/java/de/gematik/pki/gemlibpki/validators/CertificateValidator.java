package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public interface CertificateValidator {

    default void validateCertificate(@NonNull X509Certificate x509EeCert) throws GemPkiException {
        validateCertificate(x509EeCert, ZonedDateTime.now(ZoneOffset.UTC), new ValidationContext());
    }

    default void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate) throws GemPkiException {
        validateCertificate(x509EeCert, referenceDate, new ValidationContext());
    }

    void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate, @NonNull ValidationContext context)
            throws GemPkiException;

    @Getter
    @Setter
    class ValidationContext {
        String ocspAddress;
    }
}
