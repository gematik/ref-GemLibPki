package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.ocsp.TucPki006OcspVerifier;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class OCSPValidator implements CertificateValidator {

    @NonNull
    private final String productType;
    @NonNull
    private final List<TspService> tspServiceList;

    private final boolean withOcspCheck;
    private final OCSPResp ocspResponse;
    private final OcspRespCache ocspRespCache;
    private final int ocspTimeoutSeconds;
    private final boolean tolerateOcspFailure;


    /**
     * Verify signature of parameterized end-entity certificate against given issuer certificate.
     * Issuer certificate (CA) is determined from TSL file.
     *
     * @throws GemPkiException if certificate is mathematically invalid
     */
    @Override
    public void validateCertificate(@NonNull X509Certificate x509EeCert, @NonNull ZonedDateTime referenceDate, @NonNull ValidationContext context) throws GemPkiException {
        if (!withOcspCheck) {
            log.warn(ErrorCode.SW_1039_NO_OCSP_CHECK.getErrorMessage(productType));
            return;
        }

        final TspServiceSubset tspServiceSubset = new TspInformationProvider(tspServiceList, productType).getIssuerTspServiceSubset(x509EeCert);

        final X509Certificate x509IssuerCert = tspServiceSubset.getX509IssuerCert();

        final OcspTransceiver transceiver =
                OcspTransceiver.builder()
                        .productType(productType)
                        .tspServiceList(tspServiceList)
                        .x509EeCert(x509EeCert)
                        .x509IssuerCert(x509IssuerCert)
                        .ssp(tspServiceSubset.getServiceSupplyPoint())
                        .ocspTimeoutSeconds(ocspTimeoutSeconds)
                        .tolerateOcspFailure(tolerateOcspFailure)
                        .build();

        if (ocspResponse != null) {
            try {
                final TucPki006OcspVerifier verifier = transceiver.getTucPki006Verifier(ocspResponse);
                verifier.performTucPki006Checks(referenceDate);
                return;

            } catch (final GemPkiException e) {
                log.warn(ErrorCode.TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID.getErrorMessage(productType));
            }
        }
        context.setOcspAddress(tspServiceSubset.getServiceSupplyPoint());

        transceiver.verifyOcspResponse(ocspRespCache, referenceDate);
    }
}
