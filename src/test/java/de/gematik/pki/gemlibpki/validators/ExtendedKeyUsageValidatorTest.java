package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.*;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class ExtendedKeyUsageValidatorTest {

    private final static CertificateProfile CERTIFICATE_PROFILE = CERT_PROFILE_C_HCI_AUT_ECC;

    private ExtendedKeyUsageValidator tested;

    @BeforeEach
    void setUp() {
        tested = new ExtendedKeyUsageValidator(PRODUCT_TYPE);
    }

    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new ExtendedKeyUsageValidator(null), "productType");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        assertNonNullParameter(() -> tested.validateCertificate(null, CERTIFICATE_PROFILE), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, null), "certificateProfile");
    }

    @Test
    void verifyExtendedKeyUsageMissingInCertificateAndNotExpected() {
        assertDoesNotThrow(() -> tested.validateCertificate(MISSING_EXT_KEY_USAGE_EE_CERT, CERT_PROFILE_ANY));
    }

    @Test
    void verifyExtendedKeyUsageNotChecked() {

        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERT_PROFILE_ANY));
    }

    @Test
    void verifyExtendedKeyUsageValid() {
        assertDoesNotThrow(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERTIFICATE_PROFILE));
    }

    @Test
    void verifyNotAllExtendedKeyUsagesPresentInCert() throws GemPkiException {

        assertThatThrownBy(() -> tested.validateCertificate(VALID_X509_EE_CERT_SMCB, CERT_PROFILE_C_HP_AUT_ECC))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyToManyExtendedKeyUsagesPresentInCert() {
        assertThatThrownBy(() -> tested.validateCertificate(VALID_HBA_AUT_ECC, CERT_PROFILE_C_HCI_AUT_ECC))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyExtendedKeyUsageMissingInCertificate() {
        assertThatThrownBy(() -> tested.validateCertificate(MISSING_EXT_KEY_USAGE_EE_CERT, CERTIFICATE_PROFILE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyExtendedKeyUsageInvalidInCertificate() {
        X509Certificate invalidExtendedKeyUsageEeCert = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");

        assertThatThrownBy(() -> tested.validateCertificate(invalidExtendedKeyUsageEeCert, CERTIFICATE_PROFILE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyExtendedKeyUsageCertificateParsingException()
            throws CertificateParsingException {

        final X509Certificate cert = Mockito.spy(VALID_X509_EE_CERT_SMCB);
        Mockito.when(cert.getExtendedKeyUsage()).thenThrow(new CertificateParsingException());

        assertThatThrownBy(() -> tested.validateCertificate(cert, CERTIFICATE_PROFILE))
                .isInstanceOf(GemPkiRuntimeException.class)
                .hasMessage(
                        "Fehler beim Lesen der ExtendedKeyUsages des Zertifikats: CN=Zahnarztpraxis Dr."
                                + " med.Gunther KZV"
                                + " TEST-ONLY,2.5.4.5=#131731372e3830323736383833313139313130303033333237,O=2-2.30.1.16.TestOnly"
                                + " NOT-VALID,C=DE");
    }

}