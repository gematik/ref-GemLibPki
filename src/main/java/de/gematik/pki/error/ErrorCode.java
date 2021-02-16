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

package de.gematik.pki.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {
    //refer to document "Übergreifende Spezifikation PKI" [gemSpec_PKI], download at https://fachportal.gematik.de/downloadcenter/releases

    TE_1001(ErrorSeverity.ERROR, ErrorClassifier.TECHNICAL_ERROR, "TSL_INIT_ERROR",
        "Es liegt keine gültige TSL vor"),

    TE_1026(ErrorSeverity.ERROR, ErrorClassifier.TECHNICAL_ERROR, "SERVICESUPPLYPOINT_MISSING",
        "Das Element „Service-Supply Point“ konnte nicht gefunden werden."),

    TE_1027(ErrorSeverity.ERROR, ErrorClassifier.TECHNICAL_ERROR, "CA_CERT_MISSING",
        "CA kann nicht in den TSL- Informationen ermittelt werden."),

    TE_1002(ErrorSeverity.ERROR, ErrorClassifier.TECHNICAL_ERROR,
        "TSL_CERT_EXTRACTION_ERROR",
        "Zertifikate lassen sich nicht extrahieren"),

    SE_1003(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "MULTIPLE_TRUST_ANCHOR",
        "Mehr als ein markierter V-Anker gefunden"),

    SE_1007(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "TSL_ID_INCORRECT",
        "Vergleich der ID und Sequence- Number entspricht nicht der Vergleichsvariante 6a"),

    SE_1016(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "WRONG_KEYUSAGE",
        "KeyUsage ist nicht vorhanden bzw. entspricht nicht der vorgesehenen KeyUsage"),

    SE_1018(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CERT_TYPE_MISMATCH",
        "Zertifikatstyp OID stimmt nicht überein."),

    SE_1017(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "WRONG_EXTENDEDKEYUSAGE",
        "Extended KeyUsage entspricht nicht der vorgesehenen Extended KeyUsage"),

    SE_1021(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CERTIFICATE_NOT_VALID_TIME",
        "Zertifikat ist zeitlich nicht gültig"),

    SE_1023(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "AUTHORITYKEYID_DIFFERENT",
        "Authority Key Identifier des End Entity Zertifikats von "
            + "Subject Key Identifier des CA Zertifikats unterschiedlich."),

    SE_1024(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CERTIFICATE_NOT_VALID_MATH",
        "Zertifikats-Signatur ist mathematisch nicht gültig."),

    SE_1033(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CERT_TYPE_INFO_MISSING",
        "Kein Element PolicyIdentifier vorhanden."),

    SE_1036(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CA_CERTIFICATE_REVOKED_IN_TSL",
        "Das Zertifikat ist ungültig. Es wurde nach der Sperrung der ausgebenden CA ausgestellt."),

    SE_1061(ErrorSeverity.ERROR, ErrorClassifier.SECURITY_ERROR, "CERT_TYPE_CA_NOT_AUTHORIZED",
        "CA (laut TSL) nicht autorisiert für die Herausgabe dieses Zertifikatstyps."),

    // library internal errors
    UNKNOWN(ErrorSeverity.ERROR, ErrorClassifier.INTERNAL_ERROR, "UNKNOWN_INTERNAL_ERROR",
        "Ein unbekannter, interner Fehler ist aufgetreten."),

    CERTIFICATE_READ(ErrorSeverity.ERROR, ErrorClassifier.INTERNAL_ERROR, "EE_CERTIFICATE_READ_ERROR",
        "Es ist ein Fehler beim Lesen des EndEntity Zertifikats aufgetreten.");

    private final ErrorSeverity errorSeverity;
    private final ErrorClassifier errorClassifier;
    private final String errorTextShort;
    private final String errorTextDesc;

    public String getErrorMessage(final String productType) {
        return "\n" + productType + ":PKI - " + getErrorClassifier().name() + " " + name() + " - "
            + getErrorTextShort()
            + " "
            + getErrorTextDesc();
    }
}
