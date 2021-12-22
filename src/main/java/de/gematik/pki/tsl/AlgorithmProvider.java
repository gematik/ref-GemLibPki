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

package de.gematik.pki.tsl;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.providers.AlgorithmsProviderEx;

/**
 * Implementation of AlgorithmsProviderEx to feed the XadesSigner
 */
class AlgorithmProvider implements AlgorithmsProviderEx {

    @Override
    public Algorithm getSignatureAlgorithm(final String keyAlgorithmName) throws UnsupportedAlgorithmException {

        switch (keyAlgorithmName) {
            case "RSA":
                return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
            case "EC":
                return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
            default:
                throw new UnsupportedAlgorithmException("Signature algorithm not supported by the provider", keyAlgorithmName);
        }
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForSignature() {
        return new ExclusiveCanonicalXMLWithoutComments();
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForTimeStampProperties() {
        return new ExclusiveCanonicalXMLWithoutComments();
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences() {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties() {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties() {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
    }

}
