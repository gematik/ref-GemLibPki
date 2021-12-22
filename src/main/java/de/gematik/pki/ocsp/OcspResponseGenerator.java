/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.ocsp;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.utils.P12Container;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import lombok.Builder;
import lombok.NonNull;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Class to support OCSP response generation.
 */
@Builder
public class OcspResponseGenerator {

    @NonNull
    private final P12Container signer;

    /**
     * Create OCSP response from given OCSP request. producedAt is now (UTC).
     *
     * @param ocspReq OCSP request
     * @return OCSP response
     */
    public OCSPResp gen(final OCSPReq ocspReq) throws GemPkiException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            return gen(ocspReq, signer.getCertificate(), ZonedDateTime.now());
        } catch (final OperatorCreationException | IOException | OCSPException | CertificateEncodingException e) {
            throw new GemPkiException(ErrorCode.UNKNOWN, "Ocsp response generation failed.", e);
        }
    }

    /**
     * Create OCSP response from given OCSP request. producedAt is now (UTC).
     *
     * @param ocspReq                OCSP request
     * @param ocspResponseSignerCert certificate in OCSP response signature
     * @param dateTime               will be producedAt
     * @return OCSP response
     */
    private OCSPResp gen(@NonNull final OCSPReq ocspReq,
        @NonNull final X509Certificate ocspResponseSignerCert, @NonNull final ZonedDateTime dateTime)
        throws OperatorCreationException, IOException, OCSPException, CertificateEncodingException, GemPkiException {

        final DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
        final BasicOCSPRespBuilder basicBuilder = new BasicOCSPRespBuilder(
            SubjectPublicKeyInfo.getInstance(ocspResponseSignerCert.getPublicKey().getEncoded()),
            digCalcProv.get(CertificateID.HASH_SHA1));

        for (final Req singleRequest : ocspReq.getRequestList()) {
            addSingleResponseWithStatusGood(basicBuilder, singleRequest);
        }
        final X509CertificateHolder[] chain = {new X509CertificateHolder(ocspResponseSignerCert.getEncoded())};
        final String sigAlgo;
        switch (signer.getPrivateKey().getAlgorithm()) {
            case "RSA":
                sigAlgo = "SHA256withRSA";
                break;
            case "EC":
                sigAlgo = "SHA256WITHECDSA";
                break;
            default:
                throw new GemPkiException(ErrorCode.UNKNOWN, "Signature algorithm not supported: " + signer.getPrivateKey().getAlgorithm());
        }

        final BasicOCSPResp resp = basicBuilder.build(
            new JcaContentSignerBuilder(sigAlgo)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signer.getPrivateKey()),
            chain, new Date(dateTime.toInstant().toEpochMilli()));

        final OCSPRespBuilder builder = new OCSPRespBuilder();
        return builder.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }

    /**
     * Add a single response (without extensions) to an OCSP response
     *
     * @param basicBuilder  The basic builder of an OCSP Response
     * @param singleRequest A single request of an requestList of an OCSP request
     */
    private static void addSingleResponseWithStatusGood(final BasicOCSPRespBuilder basicBuilder,
        final Req singleRequest) {

        basicBuilder.addResponse(singleRequest.getCertID(),
            CertificateStatus.GOOD, new Date(), null,
            new Extensions(new ArrayList<Extension>().toArray(new Extension[0])));
    }

}
