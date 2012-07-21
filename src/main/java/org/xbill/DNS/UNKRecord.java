// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * A class implementing Records of unknown and/or unimplemented types. This
 * class can only be initialized using static Record initializers.
 * 
 * @author Brian Wellington
 */

public class UNKRecord extends Record {

    private static final long serialVersionUID = -4193583311594626915L;

    private byte[]            data;

    UNKRecord() {
    }

    /** Returns the contents of this record. */
    public byte[] getData() {
        return data;
    }

    @Override
    Record getObject() {
        return new UNKRecord();
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        throw st.exception("invalid unknown RR encoding");
    }

    @Override
    void rrFromWire(DNSInput in) throws IOException {
        data = in.readByteArray();
    }

    /** Converts this Record to the String "unknown format" */
    @Override
    String rrToString() {
        return unknownToString(data);
    }

    @Override
    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        out.writeByteArray(data);
    }

}
