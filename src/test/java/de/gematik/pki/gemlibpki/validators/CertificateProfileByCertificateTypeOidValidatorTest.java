package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.Policies;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class CertificateProfileByCertificateTypeOidValidatorTest {

    @Test
    void verifyConstructorNullParameter() {
        assertNonNullParameter(() -> new CertificateProfileByCertificateTypeOidValidator(null), "productType");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        X509Certificate x509EeCert = Mockito.mock(X509Certificate.class);

        CertificateProfileByCertificateTypeOidValidator tested = new CertificateProfileByCertificateTypeOidValidator(PRODUCT_TYPE);

        assertNonNullParameter(() -> tested.validateCertificate(null, CERT_PROFILE_C_HCI_AUT_ECC), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(x509EeCert, null), "certificateProfile");
    }


    @Test
    void verifyCertificateProfileInvalidCertType() throws GemPkiException {

        assertThatThrownBy(() -> doValidateCertificate(INVALID_CERT_TYPE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1018_CERT_TYPE_MISMATCH.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void multipleCertificateProfilesMultipleCertTypesInEe() {
        final X509Certificate eeMultipleCertTypes =
                TestUtils.readCert("GEM.SMCB-CA9/Aschoffsche_Apotheke_twoCertTypes.pem");
        assertDoesNotThrow(() -> doValidateCertificate(eeMultipleCertTypes));
    }


    @Test
    void verifyCertificateProfileMissingPolicyId() {
        assertThatThrownBy(() -> doValidateCertificate(MISSING_POLICY_ID_CERT))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void verifyCertificateProfileMissingCertType() {

        assertThatThrownBy(() -> doValidateCertificate(MISSING_CERT_TYPE))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(PRODUCT_TYPE));
    }

    @Test
    void testGetCertificatePolicyOidsException() {
        try (MockedConstruction<Policies> ignored = Mockito.mockConstructionWithAnswer(Policies.class, invocation -> {
            throw new IOException();
        })) {

            assertThatThrownBy(() -> doValidateCertificate(VALID_X509_EE_CERT_SMCB))
                    .isInstanceOf(GemPkiException.class)
                    .hasMessage(ErrorCode.TE_1019_CERT_READ_ERROR.getErrorMessage(PRODUCT_TYPE));
        }
    }

    private void doValidateCertificate(final X509Certificate x509EeCert) throws GemPkiException {
        new CertificateProfileByCertificateTypeOidValidator(PRODUCT_TYPE).validateCertificate(x509EeCert, CERT_PROFILE_C_HCI_AUT_ECC);
    }
}