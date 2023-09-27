package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.Policies;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
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

class CertificateTypeOidInIssuerTspServiceExtensionValidatorTest {

    @Test
    void verifyConstructorNullParameter() {
        TspServiceSubset tspServiceSubset = Mockito.mock(TspServiceSubset.class);

        assertNonNullParameter(() -> new CertificateTypeOidInIssuerTspServiceExtensionValidator(null, tspServiceSubset), "productType");
        assertNonNullParameter(() -> new CertificateTypeOidInIssuerTspServiceExtensionValidator(PRODUCT_TYPE, null), "tspServiceSubset");
    }

    @Test
    void verifyValidateCertificateNullParameter() {
        TspServiceSubset tspServiceSubset = Mockito.mock(TspServiceSubset.class);
        X509Certificate x509EeCert = Mockito.mock(X509Certificate.class);

        CertificateTypeOidInIssuerTspServiceExtensionValidator tested = new CertificateTypeOidInIssuerTspServiceExtensionValidator(PRODUCT_TYPE, tspServiceSubset);

        assertNonNullParameter(() -> tested.validateCertificate(null, CERT_PROFILE_C_HCI_AUT_ECC), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(x509EeCert, null), "certificateProfile");
    }

    @Test
    void verifyCertificateProfileWrongServiceInfoExtInTsl() {
        final String tslAltCaWrongServiceExtension = "tsls/ecc/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";

        assertThatThrownBy(() -> doValidateCertificate(tslAltCaWrongServiceExtension, VALID_X509_EE_CERT_ALT_CA))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED.getErrorMessage(PRODUCT_TYPE));
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
        X509Certificate validX509EeCert = TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");

        try (final MockedConstruction<Policies> ignored = Mockito.mockConstructionWithAnswer(Policies.class, invocation -> {
            throw new IOException();
        })) {

            assertThatThrownBy(() -> doValidateCertificate(validX509EeCert))
                    .isInstanceOf(GemPkiException.class)
                    .hasMessage(ErrorCode.TE_1019_CERT_READ_ERROR.getErrorMessage(PRODUCT_TYPE));
        }
    }

    private void doValidateCertificate(final X509Certificate x509EeCert) throws GemPkiException {
        doValidateCertificate(FILE_NAME_TSL_ECC_DEFAULT, x509EeCert);
    }

    private void doValidateCertificate(final String tslFilename, final X509Certificate x509EeCert) throws GemPkiException {

        final TspServiceSubset tspServiceSubset =
                new TspInformationProvider(
                        new TslInformationProvider(TestUtils.getTslUnsigned(tslFilename)).getTspServices(),
                        PRODUCT_TYPE)
                        .getIssuerTspServiceSubset(x509EeCert);

        new CertificateTypeOidInIssuerTspServiceExtensionValidator(PRODUCT_TYPE, tspServiceSubset).validateCertificate(x509EeCert, CERT_PROFILE_C_HCI_AUT_ECC);
    }

}