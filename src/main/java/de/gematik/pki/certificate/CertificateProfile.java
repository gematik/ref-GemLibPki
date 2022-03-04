/*
 * Copyright (c) 2022 gematik GmbH
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

import java.util.List;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enum that host {@link CertificateProfile} information.
 */

@RequiredArgsConstructor
@Getter
public enum CertificateProfile {

    C_CH_AUT_RSA(CertificateType.EGK_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH), false),
    C_CH_AUT_ECC(CertificateType.EGK_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH), false),

    C_HP_AUT_RSA(CertificateType.HBA_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH, ExtendedKeyUsage.ID_KP_EMAILPROTECTION), true),
    C_HP_AUT_ECC(CertificateType.HBA_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_AGREEMENT),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH, ExtendedKeyUsage.ID_KP_EMAILPROTECTION), true),

    C_HCI_AUT_RSA(CertificateType.SMC_B_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH), true),
    C_HCI_AUT_ECC(CertificateType.SMC_B_AUT, List.of(KeyUsage.DIGITAL_SIGNATURE),
        List.of(ExtendedKeyUsage.ID_KP_CLIENTAUTH), true),

    C_HCI_ENC_RSA(CertificateType.SMC_B_ENC, List.of(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DATA_ENCIPHERMENT), List.of(), false),
    C_HCI_ENC_ECC(CertificateType.SMC_B_ENC, List.of(KeyUsage.KEY_AGREEMENT), List.of(), false),

    C_HCI_OSIG(CertificateType.SMC_B_OSIG, List.of(KeyUsage.NON_REPUDIATION), List.of(), false),

    C_FD_SIG(CertificateType.FD_SIG, List.of(KeyUsage.DIGITAL_SIGNATURE), List.of(), false),
    C_FD_OSIG(CertificateType.FD_OSIG, List.of(KeyUsage.NON_REPUDIATION), List.of(), false),

    C_TSL_SIG_RSA(CertificateType.NONE, List.of(KeyUsage.NON_REPUDIATION), List.of(ExtendedKeyUsage.ID_TSL_KP_TSLSIGNING), true),

    C_TSL_SIG_ECC(CertificateType.NONE, C_TSL_SIG_RSA.keyUsages, C_TSL_SIG_RSA.extKeyUsages, true);

    private final CertificateType certificateType;
    private final List<KeyUsage> keyUsages;
    private final List<ExtendedKeyUsage> extKeyUsages;
    private final boolean failOnMissingEku;

}
