package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

@Slf4j
@RequiredArgsConstructor
public class SignatureValidator implements CertificateValidator {

    @NonNull
    private final String productType;
    @NonNull
    private final X509Certificate x509IssuerCert;


    /**
     * Verify signature of parameterized end-entity certificate against given issuer certificate.
     * Issuer certificate (CA) is determined from TSL file.
     *
     * @throws GemPkiException if certificate is mathematically invalid
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate, @NonNull ValidationContext context) throws GemPkiException {

        try {
            x509EeCert.verify(x509IssuerCert.getPublicKey());
            log.debug("Signature verification for end entity certificate successful.");
        } catch (final GeneralSecurityException verifyFailed) {
            throw new GemPkiException(
                    productType, ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH, verifyFailed);
        }
    }
}
