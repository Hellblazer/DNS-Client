// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Implements common functionality for the many record types whose format is a
 * list of strings.
 * 
 * @author Brian Wellington
 */

abstract class TXTBase extends Record {

    private static final long serialVersionUID = -4319510507246305931L;

    protected List<byte[]>    strings;

    protected TXTBase() {
    }

    protected TXTBase(Name name, int type, int dclass, long ttl) {
        super(name, type, dclass, ttl);
    }

    protected TXTBase(Name name, int type, int dclass, long ttl, List<?> strings) {
        super(name, type, dclass, ttl);
        if (strings == null) {
            throw new IllegalArgumentException("strings must not be null");
        }
        this.strings = new ArrayList<byte[]>(strings.size());
        Iterator<?> it = strings.iterator();
        try {
            while (it.hasNext()) {
                String s = (String) it.next();
                this.strings.add(byteArrayFromString(s));
            }
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    protected TXTBase(Name name, int type, int dclass, long ttl, String string) {
        this(name, type, dclass, ttl, Collections.singletonList(string));
    }

    /**
     * Returns the text strings
     * 
     * @return A list of Strings corresponding to the text strings.
     */
    public List<String> getStrings() {
        List<String> list = new ArrayList<String>(strings.size());
        for (int i = 0; i < strings.size(); i++) {
            list.add(byteArrayToString((byte[]) strings.get(i), false));
        }
        return list;
    }

    /**
     * Returns the text strings
     * 
     * @return A list of byte arrays corresponding to the text strings.
     */
    public List<byte[]> getStringsAsByteArrays() {
        return strings;
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        strings = new ArrayList<byte[]>(2);
        while (true) {
            Tokenizer.Token t = st.get();
            if (!t.isString()) {
                break;
            }
            try {
                strings.add(byteArrayFromString(t.value));
            } catch (TextParseException e) {
                throw st.exception(e.getMessage());
            }

        }
        st.unget();
    }

    @Override
    void rrFromWire(DNSInput in) throws IOException {
        strings = new ArrayList<byte[]>(2);
        while (in.remaining() > 0) {
            byte[] b = in.readCountedString();
            strings.add(b);
        }
    }

    /** converts to a String */
    @Override
    String rrToString() {
        StringBuffer sb = new StringBuffer();
        Iterator<byte[]> it = strings.iterator();
        while (it.hasNext()) {
            byte[] array = (byte[]) it.next();
            sb.append(byteArrayToString(array, true));
            if (it.hasNext()) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    @Override
    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        Iterator<byte[]> it = strings.iterator();
        while (it.hasNext()) {
            byte[] b = (byte[]) it.next();
            out.writeCountedString(b);
        }
    }

}
