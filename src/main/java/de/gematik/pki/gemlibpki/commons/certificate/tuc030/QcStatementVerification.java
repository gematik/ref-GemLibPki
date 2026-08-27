/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.commons.certificate.tuc030;

import static de.gematik.pki.gemlibpki.commons.error.ErrorCode.TE_1048_QC_STATEMENT_ERROR;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;

@Slf4j
public class QcStatementVerification {

  public static void checkQcStatementPresent(
      final String productType, @NonNull final X509Certificate x509Cert) throws GemPkiException {
    final List<ASN1Sequence> qcStatements = readQcStatements(x509Cert);
    if (qcStatements.isEmpty()) {
      throw new GemPkiException(productType, TE_1048_QC_STATEMENT_ERROR);
    }
    qcStatements.stream()
        .filter(seq -> seq.size() > 0)
        .map(seq -> seq.getObjectAt(0))
        .filter(
            obj -> obj.toString().equals(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()))
        .findFirst()
        .orElseThrow(() -> new GemPkiException(productType, TE_1048_QC_STATEMENT_ERROR));

    log.info("QCStatements found: {}", qcStatements);
  }

  public static List<ASN1Sequence> readQcStatements(@NonNull final X509Certificate x509Cert) {
    try {
      final X509CertificateHolder certHolder =
          new X509CertificateHolder(GemLibPkiUtils.certToBytes(x509Cert));
      final Extension ext = certHolder.getExtension(Extension.qCStatements);
      if (ext == null) {
        return Collections.emptyList();
      }
      final ASN1InputStream asn1InputStream = new ASN1InputStream(ext.getExtnValue().getOctets());
      final ASN1Primitive asn1Primitive = asn1InputStream.readObject();
      asn1InputStream.close();
      final ASN1Sequence qcSeq = ASN1Sequence.getInstance(asn1Primitive);
      final List<ASN1Sequence> result = new ArrayList<>();
      for (int i = 0; i < qcSeq.size(); i++) {
        result.add(ASN1Sequence.getInstance(qcSeq.getObjectAt(i)));
      }
      return result;
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Error reading QCStatements", e);
    }
  }
}
