// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;

/**
 * IPv6 Address Record - maps a domain name to an IPv6 address
 * 
 * @author Brian Wellington
 */

public class AAAARecord extends Record {

    private static final long serialVersionUID = -4588601512069748050L;

    private InetAddress       address;

    /**
     * Creates an AAAA Record from the given data
     * 
     * @param address
     *            The address suffix
     */
    public AAAARecord(Name name, int dclass, long ttl, InetAddress address) {
        super(name, Type.AAAA, dclass, ttl);
        if (Address.familyOf(address) != Address.IPv6) {
            throw new IllegalArgumentException("invalid IPv6 address");
        }
        this.address = address;
    }

    AAAARecord() {
    }

    /** Returns the address */
    public InetAddress getAddress() {
        return address;
    }

    @Override
    Record getObject() {
        return new AAAARecord();
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        address = st.getAddress(Address.IPv6);
    }

    @Override
    void rrFromWire(DNSInput in) throws IOException {
        address = InetAddress.getByAddress(in.readByteArray(16));
    }

    /** Converts rdata to a String */
    @Override
    String rrToString() {
        return address.getHostAddress();
    }

    @Override
    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        out.writeByteArray(address.getAddress());
    }

}
