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

package de.gematik.pki.certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum CertificateType {

    EGK_AUT("C.CH.AUT", "oid_egk_aut", "1.2.276.0.76.4.70"),
    HBA_AUT("C.HP.AUT", "oid_hba_aut", "1.2.276.0.76.4.75"),
    SMC_B_AUT("C.HCI.AUT", "oid_smc_b_aut", "1.2.276.0.76.4.77"),
    SMC_B_ENC("C.HCI.ENC", "oid_smc_b_enc", "1.2.276.0.76.4.76"),
    NONE("", "", "");

    private final String name;
    private final String oidReference;
    private final String oid;
}
