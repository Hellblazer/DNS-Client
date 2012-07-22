// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * Mailbox information Record - lists the address responsible for a mailing
 * list/mailbox and the address to receive error messages relating to the
 * mailing list/mailbox.
 * 
 * @author Brian Wellington
 */

public class MINFORecord extends Record {

    private static final long serialVersionUID = -3962147172340353796L;

    private Name              errorAddress;
    private Name              responsibleAddress;

    /**
     * Creates an MINFO Record from the given data
     * 
     * @param responsibleAddress
     *            The address responsible for the mailing list/mailbox.
     * @param errorAddress
     *            The address to receive error messages relating to the mailing
     *            list/mailbox.
     */
    public MINFORecord(Name name, int dclass, long ttl,
                       Name responsibleAddress, Name errorAddress) {
        super(name, Type.MINFO, dclass, ttl);

        this.responsibleAddress = checkName("responsibleAddress",
                                            responsibleAddress);
        this.errorAddress = checkName("errorAddress", errorAddress);
    }

    MINFORecord() {
    }

    /**
     * Gets the address to receive error messages relating to the mailing
     * list/mailbox.
     */
    public Name getErrorAddress() {
        return errorAddress;
    }

    /** Gets the address responsible for the mailing list/mailbox. */
    public Name getResponsibleAddress() {
        return responsibleAddress;
    }

    @Override
    Record getObject() {
        return new MINFORecord();
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        responsibleAddress = st.getName(origin);
        errorAddress = st.getName(origin);
    }

    @Override
    void rrFromWire(DNSInput in) throws IOException {
        responsibleAddress = new Name(in);
        errorAddress = new Name(in);
    }

    /** Converts the MINFO Record to a String */
    @Override
    String rrToString() {
        StringBuffer sb = new StringBuffer();
        sb.append(responsibleAddress);
        sb.append(" ");
        sb.append(errorAddress);
        return sb.toString();
    }

    @Override
    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        responsibleAddress.toWire(out, null, canonical);
        errorAddress.toWire(out, null, canonical);
    }

}
