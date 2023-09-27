package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.*;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class KeyUsageValidatorTest {

    private final static CertificateProfile CERTIFICATE_PROFILE = CERT_PROFILE_C_HCI_AUT_ECC;
    private final static X509Certificate VALID_X_509_EE_CERT = TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
    private KeyUsageValidator tested;

    @BeforeEach
    void setUp() {
        tested = new KeyUsageValidator(PRODUCT_TYPE);
    }

    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new KeyUsageValidator(null), "productType");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        assertNonNullParameter(() -> tested.validateCertificate(null, CERTIFICATE_PROFILE), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(VALID_X_509_EE_CERT, null), "certificateProfile");
    }


    @Test
    void verifyKeyUsageValid() {
        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X_509_EE_CERT, CERTIFICATE_PROFILE));
    }

    @Test
    void verifyKeyUsageInvalidInCertificateButNotChecked() {
        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERT_PROFILE_ANY));
    }

    @Test
    void verifyKeyUsageMissingInCertificate() {
        X509Certificate missingKeyUsages509EeCert = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");

        assertThatThrownBy(() -> tested.validateCertificate(missingKeyUsages509EeCert, CERTIFICATE_PROFILE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyKeyUsageInvalidInCertificate() {

        assertThatThrownBy(() -> tested.validateCertificate(VALID_X509_EE_CERT_INVALID_KEY_USAGE, CERTIFICATE_PROFILE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyNotAllKeyUsagesPresentInCert() {
        assertThatThrownBy(() -> tested.validateCertificate(VALID_X_509_EE_CERT, CERT_PROFILE_C_HCI_AUT_RSA))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyToManyKeyUsagesPresentInCert() {
        assertThatThrownBy(() -> tested.validateCertificate(VALID_HBA_AUT_ECC, CERT_PROFILE_C_HCI_AUT_ECC))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

}