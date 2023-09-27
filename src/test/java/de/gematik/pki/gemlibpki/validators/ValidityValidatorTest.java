package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class ValidityValidatorTest {

    private static final X509Certificate VALID_X509_EE_CERT = TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
    private static final ZonedDateTime ZONED_DATE_TIME = ZonedDateTime.parse("2020-11-20T15:00:00Z");
    private ValidityValidator tested;

    @BeforeEach
    void setUp() {
        tested = new ValidityValidator(PRODUCT_TYPE);
    }

    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new ValidityValidator(null), "productType");
    }

    @Test
    void verifyValidateCertificateNullParameter() {

        assertNonNullParameter(() -> tested.validateCertificate(null), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, ZONED_DATE_TIME), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, ZONED_DATE_TIME, new CertificateValidator.ValidationContext()), "x509EeCert");


        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT, null), "referenceDate");
        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT, null, new CertificateValidator.ValidationContext()), "referenceDate");

        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT, ZONED_DATE_TIME, null), "context");
    }


    @Test
    void verifyValidityCertificateExpired() {
        X509Certificate expiredEeCert = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem");

        assertThatThrownBy(() -> tested.validateCertificate(expiredEeCert, ZONED_DATE_TIME))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyValidityCertificateNotYetValid() {
        X509Certificate notYetValidEeCert = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem");

        assertThatThrownBy(() -> tested.validateCertificate(notYetValidEeCert, ZONED_DATE_TIME))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyValidityCertificateValid() {
        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT, ZONED_DATE_TIME));
    }

}