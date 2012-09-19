/** 
 * (C) Copyright 2012 Hal Hildebrand, all rights reserved.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.xbill.DNS;

import java.io.IOException;

/**
 * @author hhildebrand
 * 
 */
public class UpdateLeaseOption extends EDNSOption {
    private long lease;

    public UpdateLeaseOption(long lease) {
        super(Code.UPDATE_LEASE);
        this.lease = lease;
    }

    public long getLease() {
        return lease;
    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionFromWire(org.xbill.DNS.DNSInput)
     */
    @Override
    void optionFromWire(DNSInput in) throws IOException {
        lease = in.readU32();
    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionToString()
     */
    @Override
    String optionToString() {
        return String.format("UPDATE_LEASE %S seconds", lease);
    }

    /* (non-Javadoc)
     * @see org.xbill.DNS.EDNSOption#optionToWire(org.xbill.DNS.DNSOutput)
     */
    @Override
    void optionToWire(DNSOutput out) {
        out.writeU32(lease);
    }

}
