// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Mail Destination Record - specifies a mail agent which delivers mail for a
 * domain (obsolete)
 * 
 * @author Brian Wellington
 */

public class MDRecord extends SingleNameBase {

    private static final long serialVersionUID = 5268878603762942202L;

    /**
     * Creates a new MD Record with the given data
     * 
     * @param mailAgent
     *            The mail agent that delivers mail for the domain.
     */
    public MDRecord(Name name, int dclass, long ttl, Name mailAgent) {
        super(name, Type.MD, dclass, ttl, mailAgent, "mail agent");
    }

    MDRecord() {
    }

    @Override
    public Name getAdditionalName() {
        return getSingleName();
    }

    /** Gets the mail agent for the domain */
    public Name getMailAgent() {
        return getSingleName();
    }

    @Override
    Record getObject() {
        return new MDRecord();
    }

}
