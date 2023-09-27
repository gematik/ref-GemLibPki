package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CriticalExtensionsValidatorTest {

    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new CriticalExtensionsValidator(null), "productType");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        X509Certificate x509EeCert = Mockito.mock(X509Certificate.class);

        CriticalExtensionsValidator tested = new CriticalExtensionsValidator(PRODUCT_TYPE);

        assertNonNullParameter(() -> tested.validateCertificate(null, CERT_PROFILE_C_HCI_AUT_ECC), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(x509EeCert, null), "certificateProfile");
    }


    @Test
    void verifyCriticalExtensions() {
        final X509Certificate certInvalidCriticalExtension = TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-extension-crit.pem");

        CriticalExtensionsValidator tested = new CriticalExtensionsValidator(PRODUCT_TYPE);

        assertThatThrownBy(() -> tested.validateCertificate(certInvalidCriticalExtension, CERT_PROFILE_C_HCI_AUT_ECC))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION.getErrorMessage(PRODUCT_TYPE));
    }

}