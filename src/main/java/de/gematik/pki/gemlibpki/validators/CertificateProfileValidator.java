package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import lombok.NonNull;

import java.security.cert.X509Certificate;

public interface CertificateProfileValidator {

    void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile)
            throws GemPkiException;

}
