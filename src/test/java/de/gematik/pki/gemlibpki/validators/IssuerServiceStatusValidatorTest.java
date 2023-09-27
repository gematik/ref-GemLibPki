package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import lombok.NonNull;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;

import static de.gematik.pki.gemlibpki.TestConstants.*;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class IssuerServiceStatusValidatorTest {

    @Test
    void verifyConstructorNullParameter() {

        TspServiceSubset tspServiceSubset = Mockito.mock(TspServiceSubset.class);

        assertNonNullParameter(() -> new IssuerServiceStatusValidator(null, tspServiceSubset), "productType");
        assertNonNullParameter(() -> new IssuerServiceStatusValidator(PRODUCT_TYPE, null), "tspServiceSubset");
    }


    @Test
    void verifyValidateCertificateNullParameter() {
        TspServiceSubset tspServiceSubset = Mockito.mock(TspServiceSubset.class);
        ZonedDateTime zonedDateTime = Mockito.mock(ZonedDateTime.class);

        IssuerServiceStatusValidator tested = new IssuerServiceStatusValidator(PRODUCT_TYPE, tspServiceSubset);

        assertNonNullParameter(() -> tested.validateCertificate(null), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime), "x509EeCert");
        assertNonNullParameter(() -> tested.validateCertificate(null, zonedDateTime, new CertificateValidator.ValidationContext()), "x509EeCert");


        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_ALT_CA, null), "referenceDate");
        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_ALT_CA, null, new CertificateValidator.ValidationContext()), "referenceDate");

        assertNonNullParameter(() -> tested.validateCertificate(VALID_X509_EE_CERT_ALT_CA, zonedDateTime, null), "context");
    }


    @Test
    void verifyIssuerServiceStatusNotRevoked() {
        assertDoesNotThrow(() -> doValidateCertificate(FILE_NAME_TSL_ECC_ALT_CA, VALID_X509_EE_CERT_ALT_CA));
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is before StatusStartingTime of TSPService
     * (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevokedLater() {
        final String tslAltCaRevokedLater = "tsls/ecc/valid/TSL_altCA_revokedLater.xml";
        assertDoesNotThrow(() -> doValidateCertificate(tslAltCaRevokedLater, VALID_X509_EE_CERT_ALT_CA));
    }

    /**
     * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is after StatusStartingTime of TSPService
     * (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
     */
    @Test
    void verifyIssuerServiceStatusRevoked() {

        assertThatThrownBy(() -> doValidateCertificate("tsls/ecc/valid/TSL_altCA_revoked.xml", VALID_X509_EE_CERT_ALT_CA))
                .isInstanceOf(GemPkiException.class)
                .hasMessage(ErrorCode.SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL.getErrorMessage(PRODUCT_TYPE));
    }


    private void doValidateCertificate(@NonNull final String tslFilename, final X509Certificate x509EeCert) throws GemPkiException {

        List<TspService> tspServices = new TslInformationProvider(TestUtils.getTslUnsigned(tslFilename)).getTspServices();
        TspServiceSubset tspServiceSubset = new TspInformationProvider(tspServices, PRODUCT_TYPE).getIssuerTspServiceSubset(x509EeCert);

        IssuerServiceStatusValidator tested = new IssuerServiceStatusValidator(PRODUCT_TYPE, tspServiceSubset);

        tested.validateCertificate(x509EeCert);
    }


}