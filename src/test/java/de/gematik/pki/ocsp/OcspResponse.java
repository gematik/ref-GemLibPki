/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.ocsp;

import de.gematik.pki.utils.P12Content;
import de.gematik.pki.utils.P12Reader;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import lombok.NonNull;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Class to support OCSP response generation. OCSP response are generated in test only.
 */
public class OcspResponse {

    private static final String P12_OCSP_RESPONSE_SIGNER_RSA = "src/test/resources/certificates/ocsp/rsaOcspSigner.p12";

    private static P12Content ocspSigner = null;

    public OcspResponse()
        throws IOException {
        ocspSigner = P12Reader
            .getContentFromP12(FileUtils.readFileToByteArray(new File(P12_OCSP_RESPONSE_SIGNER_RSA)), "00");
    }

    /**
     * Create OCSP response from given OCSP request. producedAt is now (UTC).
     *
     * @param ocspReq OCSP request
     * @return OCSP response
     */
    public OCSPResp gen(final OCSPReq ocspReq)
        throws OperatorCreationException, CertificateEncodingException, OCSPException, IOException {
        return gen(ocspReq, ocspSigner.getCertificate(), ZonedDateTime.now());
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
        throws OperatorCreationException, IOException, OCSPException, CertificateEncodingException {

        final DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
        final BasicOCSPRespBuilder basicBuilder = new BasicOCSPRespBuilder(
            SubjectPublicKeyInfo.getInstance(ocspResponseSignerCert.getPublicKey().getEncoded()),
            digCalcProv.get(CertificateID.HASH_SHA1));

        for (final Req singleRequest : ocspReq.getRequestList()) {
            addSingleResponseWithStatus(basicBuilder, singleRequest);
        }
        final X509CertificateHolder[] chain = {new X509CertificateHolder(ocspResponseSignerCert.getEncoded())};
        final BasicOCSPResp resp = basicBuilder.build(
            new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(ocspSigner.getPrivateKey()),
            chain, new Date(dateTime.toInstant().toEpochMilli()));

        final OCSPRespBuilder builder = new OCSPRespBuilder();
        final OCSPResp ocspRespTx = builder.build(OCSPRespBuilder.SUCCESSFUL, resp);
        writeOcspRespToFile(ocspRespTx);
        return ocspRespTx;
    }

    /**
     * Add a single response (without extensions) to an OCSP response
     *
     * @param basicBuilder  The basic builder of an OCSP Response
     * @param singleRequest A single request of an requestList of an OCSP request
     */
    private void addSingleResponseWithStatus(final BasicOCSPRespBuilder basicBuilder,
        final Req singleRequest) {

        final List<Extension> singleResponseExtensions = new ArrayList<>();

        basicBuilder.addResponse(singleRequest.getCertID(),
            CertificateStatus.GOOD, new Date(), null,
            new Extensions(singleResponseExtensions.toArray(new Extension[0])));
    }

    public void writeOcspRespToFile(final OCSPResp ocspResp) throws IOException {
        final File logfile = createOcspResponseLogFile();
        FileUtils.writeByteArrayToFile(logfile, ocspResp.getEncoded(), false);
    }

    private File createOcspResponseLogFile() throws IOException {
        return createFileWithTimestamp("target/ocspResponse_");
    }

    private File createFileWithTimestamp(final String fileNamePrefix) throws IOException {
        final File file = new File(fileNamePrefix + ZonedDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss")) + ".dat");
        if (file.isFile()) {
            file.delete();
        }
        file.createNewFile();
        return file;
    }

}
