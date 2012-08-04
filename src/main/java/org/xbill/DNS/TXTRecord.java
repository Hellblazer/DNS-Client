// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.Arrays;
import java.util.List;

/**
 * Text - stores text strings
 * 
 * @author Brian Wellington
 */

public class TXTRecord extends TXTBase {

    private static final long serialVersionUID = -5780785764284221342L;

    /**
     * Creates a TXT Record from the given data
     * 
     * @param strings
     *            The text strings
     * @throws IllegalArgumentException
     *             One of the strings has invalid escapes
     */
    public TXTRecord(Name name, int dclass, long ttl, List<?> strings) {
        super(name, Type.TXT, dclass, ttl, strings);
    }

    /**
     * Creates a TXT Record from the given data
     * 
     * @param string
     *            One text string
     * @throws IllegalArgumentException
     *             The string has invalid escapes
     */
    public TXTRecord(Name name, int dclass, long ttl, String string) {
        super(name, Type.TXT, dclass, ttl, string);
    }

    TXTRecord() {
    }

    /**
     * Answer true if the receiver shares identical strings with the supplied
     * txt record
     * 
     * @param txt
     *            the record to compare
     * @return true if the receiver shares identical strings with the supplied
     *         txt record
     */
    public boolean sameTxt(TXTRecord txt) {
        if (strings.size() != txt.strings.size()) {
            return false;
        }
        for (int i = 0; i < strings.size(); i++) {
            if (!Arrays.equals(strings.get(i), txt.strings.get(i))) {
                return false;
            }
        }
        return false;
    }

    @Override
    Record getObject() {
        return new TXTRecord();
    }

}
