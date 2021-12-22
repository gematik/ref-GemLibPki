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

package de.gematik.pki.certificate;

import static org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_admission;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.NonNull;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Class to abstract the admission of a certificate. This class works with a parameterized variable for the certificate in its constructor. As specified by
 * gematik, there is only one admission. So this class returns the first available information.
 */
public class Admission {

    @NonNull
    private final ASN1Encodable asn1Admission;

    /**
     * Constructor
     *
     * @param x509EeCert end entity certificate to get admission information from
     * @throws CertificateEncodingException if certificate cannot be parsed
     * @throws IOException                  if certificate cannot be read
     */
    public Admission(@NonNull final X509Certificate x509EeCert) throws CertificateEncodingException, IOException {
        asn1Admission = new X509CertificateHolder(x509EeCert.getEncoded())
            .getExtensions()
            .getExtensionParsedValue(id_isismtt_at_admission);
    }

    /**
     * Reading admission authority
     *
     * @return String of the admission authority or an empty string if not present
     */
    public String getAdmissionAuthority() {
        try {
            return AdmissionSyntax.getInstance(asn1Admission).getAdmissionAuthority().getName().toString();
        } catch (final NullPointerException e) {
            return "";
        }
    }

    /**
     * Reading profession items
     *
     * @return Non duplicate list of profession items of the first profession info of the first admission in the certificate
     */
    public Set<String> getProfessionItems() {
        return Arrays.stream(AdmissionSyntax.getInstance(asn1Admission).getContentsOfAdmissions()[0].getProfessionInfos()[0].getProfessionItems())
            .map(DirectoryString::getString)
            .collect(Collectors.toSet());
    }

    /**
     * Reading profession oid's
     *
     * @return Non duplicate list of profession oid's of the first profession info of the first admission in the certificate
     */
    public Set<String> getProfessionOids() {
        return Arrays.stream(AdmissionSyntax.getInstance(asn1Admission).getContentsOfAdmissions()[0].getProfessionInfos()[0].getProfessionOIDs())
            .map(ASN1ObjectIdentifier::getId)
            .collect(Collectors.toSet());
    }

    /**
     * Reading registration number
     *
     * @return String of the registration number of the first profession info of the first admission in the certificate
     */
    public String getRegistrationNumber() {
        return AdmissionSyntax.getInstance(asn1Admission).getContentsOfAdmissions()[0].getProfessionInfos()[0].getRegistrationNumber();
    }
}
