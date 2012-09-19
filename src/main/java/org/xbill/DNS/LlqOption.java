/**
 * Copyright (c) 2012, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.xbill.DNS;

import java.io.IOException;

/**
 * @author hhildebrand
 * 
 */
public class LlqOption extends EDNSOption {
    public static int LLQ_PORT    = 5352;

    // Error Codes:
    public static int NO_ERROR    = 0;
    public static int SERV_FULL   = 1;
    public static int STATIC      = 2;
    public static int FORMAT_ERR  = 3;
    public static int NO_SUCH_LLQ = 4;
    public static int BAD_VERS    = 5;
    public static int UNKNOWN_ERR = 6;

    // LLQ Opcodes:
    public static int LLQ_SETUP   = 1;
    public static int LLQ_REFRESH = 2;
    public static int LLQ_EVENT   = 3;

    public LlqOption() {
        super(Code.LLQ);
    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionFromWire(org.xbill.DNS.DNSInput)
     */
    @Override
    void optionFromWire(DNSInput in) throws IOException {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionToString()
     */
    @Override
    String optionToString() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionToWire(org.xbill.DNS.DNSOutput)
     */
    @Override
    void optionToWire(DNSOutput out) {
        // TODO Auto-generated method stub

    }
}
