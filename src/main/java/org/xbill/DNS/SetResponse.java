// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.ArrayList;
import java.util.List;

/**
 * The Response from a query to Cache.lookupRecords() or Zone.findRecords()
 * 
 * @see Cache
 * @see Zone
 * 
 * @author Brian Wellington
 */

public class SetResponse {

    /**
     * The Cache/Zone found a CNAME when looking for the name.
     * 
     * @see CNAMERecord
     */
    static final int                 CNAME      = 4;

    /**
     * A delegation enclosing the requested name was found.
     */
    static final int                 DELEGATION = 3;

    /**
     * The Cache/Zone found a DNAME when looking for the name.
     * 
     * @see DNAMERecord
     */
    static final int                 DNAME      = 5;

    /**
     * The Zone does not contain the requested name, or the Cache has determined
     * that the name does not exist.
     */
    static final int                 NXDOMAIN   = 1;

    /**
     * The Zone contains the name, but no data of the requested type, or the
     * Cache has determined that the name exists and has no data of the
     * requested type.
     */
    static final int                 NXRRSET    = 2;
    /**
     * The Cache/Zone has successfully answered the question for the requested
     * name/type/class.
     */
    static final int                 SUCCESSFUL = 6;
    /**
     * The Cache contains no information about the requested name/type
     */
    static final int                 UNKNOWN    = 0;

    private static final SetResponse nxdomain   = new SetResponse(NXDOMAIN);

    private static final SetResponse nxrrset    = new SetResponse(NXRRSET);

    private static final SetResponse unknown    = new SetResponse(UNKNOWN);

    static SetResponse ofType(int type) {
        switch (type) {
            case UNKNOWN:
                return unknown;
            case NXDOMAIN:
                return nxdomain;
            case NXRRSET:
                return nxrrset;
            case DELEGATION:
            case CNAME:
            case DNAME:
            case SUCCESSFUL:
                SetResponse sr = new SetResponse();
                sr.type = type;
                sr.data = null;
                return sr;
            default:
                throw new IllegalArgumentException("invalid type");
        }
    }

    private Object data;

    private int    type;

    private SetResponse() {
    }

    SetResponse(int type) {
        if (type < 0 || type > 6) {
            throw new IllegalArgumentException("invalid type");
        }
        this.type = type;
        data = null;
    }

    SetResponse(int type, RRset rrset) {
        if (type < 0 || type > 6) {
            throw new IllegalArgumentException("invalid type");
        }
        this.type = type;
        data = rrset;
    }

    /** If the query was successful, return the answers */
    public RRset[] answers() {
        if (type != SUCCESSFUL) {
            return null;
        }
        List<?> l = (List<?>) data;
        return l.toArray(new RRset[l.size()]);
    }

    /**
     * If the query encountered a CNAME, return it.
     */
    public CNAMERecord getCNAME() {
        return (CNAMERecord) ((RRset) data).first();
    }

    /**
     * If the query encountered a DNAME, return it.
     */
    public DNAMERecord getDNAME() {
        return (DNAMERecord) ((RRset) data).first();
    }

    /**
     * If the query hit a delegation point, return the NS set.
     */
    public RRset getNS() {
        return (RRset) data;
    }

    /** Is the result of the lookup a CNAME? */
    public boolean isCNAME() {
        return type == CNAME;
    }

    /** Is the result of the lookup that the name is below a delegation? */
    public boolean isDelegation() {
        return type == DELEGATION;
    }

    /** Is the result of the lookup a DNAME? */
    public boolean isDNAME() {
        return type == DNAME;
    }

    /** Is the answer to the query that the name does not exist? */
    public boolean isNXDOMAIN() {
        return type == NXDOMAIN;
    }

    /** Is the answer to the query that the name exists, but the type does not? */
    public boolean isNXRRSET() {
        return type == NXRRSET;
    }

    /** Was the query successful? */
    public boolean isSuccessful() {
        return type == SUCCESSFUL;
    }

    /** Is the answer to the query unknown? */
    public boolean isUnknown() {
        return type == UNKNOWN;
    }

    /** Prints the value of the SetResponse */
    @Override
    public String toString() {
        switch (type) {
            case UNKNOWN:
                return "unknown";
            case NXDOMAIN:
                return "NXDOMAIN";
            case NXRRSET:
                return "NXRRSET";
            case DELEGATION:
                return "delegation: " + data;
            case CNAME:
                return "CNAME: " + data;
            case DNAME:
                return "DNAME: " + data;
            case SUCCESSFUL:
                return "successful";
            default:
                throw new IllegalStateException();
        }
    }

    void addRRset(RRset rrset) {
        if (data == null) {
            data = new ArrayList<Object>();
        }
        @SuppressWarnings("unchecked")
        List<RRset> l = (List<RRset>) data;
        l.add(rrset);
    }

}
