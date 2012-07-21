// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * An exception thrown when a DNS message is invalid.
 * 
 * @author Brian Wellington
 */

public class WireParseException extends IOException {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public WireParseException() {
        super();
    }

    public WireParseException(String s) {
        super(s);
    }

    public WireParseException(String s, Throwable cause) {
        super(s);
        initCause(cause);
    }

}
