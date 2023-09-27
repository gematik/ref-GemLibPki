package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SignatureValidatorTest {


    private SignatureValidator tested;

    @BeforeEach
    void setUp() {
        tested = new SignatureValidator(PRODUCT_TYPE, VALID_ISSUER_CERT_SMCB);
    }


    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new SignatureValidator(null, VALID_ISSUER_CERT_SMCB), "productType");
        assertNonNullParameter(() -> new SignatureValidator(PRODUCT_TYPE, null), "x509IssuerCert");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        ZonedDateTime zonedDateTime = Mockito.mock(ZonedDateTime.class);

        assertNonNullParameter(() -> tested.validateCertificate(null), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime, new CertificateValidator.ValidationContext()), "x509EeCert");


        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null), "referenceDate");
        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null, new CertificateValidator.ValidationContext()), "referenceDate");

        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, zonedDateTime, null), "context");
    }


    @Test
    void verifySignatureValid() {
        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB));
    }

    @Test
    void verifySignatureNotValid() throws GemPkiException {
        final X509Certificate invalidX509EeCert = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem");

        assertThatThrownBy(() -> tested.validateCertificate(invalidX509EeCert))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH.getErrorMessage(PRODUCT_TYPE));
    }


}