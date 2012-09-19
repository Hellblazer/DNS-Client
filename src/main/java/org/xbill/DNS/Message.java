// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * A DNS Message. A message is the basic unit of communication between the
 * client and server of a DNS operation. A message consists of a Header and 4
 * message sections.
 * 
 * @see Resolver
 * @see Header
 * @see Section
 * 
 * @author Brian Wellington
 */

public class Message implements Cloneable {

    /** The maximum length of a message in wire format. */
    public static final int MAXLENGTH         = 65535;

    private static Record[] emptyRecordArray  = new Record[0];

    private static RRset[]  emptyRRsetArray   = new RRset[0];
    /*
     * The message was signed and verification failed, or was not signed
     * when it should have been.
     */
    static final int        TSIG_FAILED       = 4;
    /* The message was an unsigned message in multiple-message response */
    static final int        TSIG_INTERMEDIATE = 2;
    /* The message was signed and no verification was attempted.  */
    static final int        TSIG_SIGNED       = 3;
    /* The message was not signed */
    static final int        TSIG_UNSIGNED     = 0;

    /* The message was signed and verification succeeded */
    static final int        TSIG_VERIFIED     = 1;

    /**
     * Creates a new Message with a random Message ID suitable for sending as a
     * query.
     * 
     * @param r
     *            A record containing the question
     */
    public static Message newQuery(Record r) {
        Message m = new Message();
        m.header.setOpcode(Opcode.QUERY);
        m.header.setFlag(Flags.RD);
        m.addRecord(r, Section.QUESTION);
        return m;
    }

    /**
     * Creates a new Message to contain a dynamic update. A random Message ID
     * and the zone are filled in.
     * 
     * @param zone
     *            The zone to be updated
     */
    public static Message newUpdate(Name zone) {
        return new Update(zone);
    }

    private static boolean sameSet(Record r1, Record r2) {
        return r1.getRRsetType() == r2.getRRsetType()
               && r1.getDClass() == r2.getDClass()
               && r1.getName().equals(r2.getName());
    }

    private Header         header;

    private TSIGRecord     querytsig;

    private List<Record>[] sections;

    private int            size;

    private int            tsigerror;
    private TSIG           tsigkey;

    int                    sig0start;

    int                    tsigstart;

    int                    tsigState;

    /** Creates a new Message with a random Message ID */
    public Message() {
        this(new Header());
    }

    /**
     * Creates a new Message from its DNS wire format representation
     * 
     * @param b
     *            A byte array containing the DNS Message.
     */
    public Message(byte[] b) throws IOException {
        this(new DNSInput(b));
    }

    /**
     * Creates a new Message from its DNS wire format representation
     * 
     * @param b
     *            A Byte Buffer containing the DNS Message.
     */
    public Message(ByteBuffer b) throws IOException {
        this(new DNSInput(b));
    }

    /** Creates a new Message with the specified Message ID */
    public Message(int id) {
        this(new Header(id));
    }

    @SuppressWarnings("unchecked")
    private Message(Header header) {
        sections = new List[4];
        this.header = header;
    }

    Message(DNSInput in) throws IOException {
        this(new Header(in));
        boolean isUpdate = header.getOpcode() == Opcode.UPDATE;
        boolean truncated = header.getFlag(Flags.TC);
        try {
            for (int i = 0; i < 4; i++) {
                int count = header.getCount(i);
                if (count > 0) {
                    sections[i] = new ArrayList<Record>(count);
                }
                for (int j = 0; j < count; j++) {
                    int pos = in.current();
                    Record rec = Record.fromWire(in, i, isUpdate);
                    sections[i].add(rec);
                    if (rec.getType() == Type.TSIG) {
                        tsigstart = pos;
                    }
                    if (rec.getType() == Type.SIG
                        && ((SIGRecord) rec).getTypeCovered() == 0) {
                        sig0start = pos;
                    }
                }
            }
        } catch (WireParseException e) {
            if (!truncated) {
                throw e;
            }
        }
        size = in.current();
    }

    /**
     * Adds a record to a section of the Message, and adjusts the header.
     * 
     * @see Record
     * @see Section
     */
    public void addRecord(Record r, int section) {
        if (sections[section] == null) {
            sections[section] = new LinkedList<Record>();
        }
        header.incCount(section);
        sections[section].add(r);
    }

    /**
     * Creates a copy of this Message. This is done by the Resolver before
     * adding TSIG and OPT records, for example.
     * 
     * @see Resolver
     * @see TSIGRecord
     * @see OPTRecord
     */
    @Override
    public Object clone() {
        Message m = new Message();
        for (int i = 0; i < sections.length; i++) {
            if (sections[i] != null) {
                m.sections[i] = new LinkedList<Record>(sections[i]);
            }
        }
        m.header = header.clone();
        m.size = size;
        return m;
    }

    /**
     * Determines if the given record is already present in any section.
     * 
     * @see Record
     * @see Section
     */
    public boolean findRecord(Record r) {
        for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
            if (sections[i] != null && sections[i].contains(r)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines if the given record is already present in the given section.
     * 
     * @see Record
     * @see Section
     */
    public boolean findRecord(Record r, int section) {
        return sections[section] != null && sections[section].contains(r);
    }

    /**
     * Determines if an RRset with the given name and type is already present in
     * any section.
     * 
     * @see RRset
     * @see Section
     */
    public boolean findRRset(Name name, int type) {
        return findRRset(name, type, Section.ANSWER)
               || findRRset(name, type, Section.AUTHORITY)
               || findRRset(name, type, Section.ADDITIONAL);
    }

    /**
     * Determines if an RRset with the given name and type is already present in
     * the given section.
     * 
     * @see RRset
     * @see Section
     */
    public boolean findRRset(Name name, int type, int section) {
        if (sections[section] == null) {
            return false;
        }
        for (int i = 0; i < sections[section].size(); i++) {
            Record r = sections[section].get(i);
            if (r.getType() == type && name.equals(r.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieves the Header.
     * 
     * @see Header
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Returns the OPT record from the ADDITIONAL section, if one is present.
     * 
     * @see OPTRecord
     * @see Section
     */
    public OPTRecord getOPT() {
        Record[] additional = getSectionArray(Section.ADDITIONAL);
        for (Record element : additional) {
            if (element instanceof OPTRecord) {
                return (OPTRecord) element;
            }
        }
        return null;
    }

    /**
     * Returns the first record in the QUESTION section.
     * 
     * @see Record
     * @see Section
     */
    public Record getQuestion() {
        List<?> l = sections[Section.QUESTION];
        if (l == null || l.size() == 0) {
            return null;
        }
        return (Record) l.get(0);
    }

    /**
     * Returns the message's rcode (error code). This incorporates the EDNS
     * extended rcode.
     */
    public int getRcode() {
        int rcode = header.getRcode();
        OPTRecord opt = getOPT();
        if (opt != null) {
            rcode += opt.getExtendedRcode() << 4;
        }
        return rcode;
    }

    /**
     * Returns an array containing all records in the given section, or an empty
     * array if the section is empty.
     * 
     * @see Record
     * @see Section
     */
    public Record[] getSectionArray(int section) {
        if (sections[section] == null) {
            return emptyRecordArray;
        }
        List<?> l = sections[section];
        return l.toArray(new Record[l.size()]);
    }

    /**
     * Returns a list containing all records in the given section, or an empty
     * list if the section is empty.
     * 
     * @see Record
     * @see Section
     */
    public List<Record> getSectionList(int section) {
        if (sections[section] == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(sections[section]);
    }

    /**
     * Returns an array containing all records in the given section grouped into
     * RRsets.
     * 
     * @see RRset
     * @see Section
     */
    public RRset[] getSectionRRsets(int section) {
        if (sections[section] == null) {
            return emptyRRsetArray;
        }
        List<RRset> sets = new LinkedList<RRset>();
        Record[] recs = getSectionArray(section);
        Set<Name> hash = new HashSet<Name>();
        for (Record rec : recs) {
            Name name = rec.getName();
            boolean newset = true;
            if (hash.contains(name)) {
                for (int j = sets.size() - 1; j >= 0; j--) {
                    RRset set = sets.get(j);
                    if (set.getType() == rec.getRRsetType()
                        && set.getDClass() == rec.getDClass()
                        && set.getName().equals(name)) {
                        set.addRR(rec);
                        newset = false;
                        break;
                    }
                }
            }
            if (newset) {
                RRset set = new RRset(rec);
                sets.add(set);
                hash.add(name);
            }
        }
        return sets.toArray(new RRset[sets.size()]);
    }

    /**
     * Returns the TSIG record from the ADDITIONAL section, if one is present.
     * 
     * @see TSIGRecord
     * @see TSIG
     * @see Section
     */
    public TSIGRecord getTSIG() {
        int count = header.getCount(Section.ADDITIONAL);
        if (count == 0) {
            return null;
        }
        List<?> l = sections[Section.ADDITIONAL];
        Record rec = (Record) l.get(count - 1);
        if (rec.type != Type.TSIG) {
            return null;
        }
        return (TSIGRecord) rec;
    }

    /**
     * Was this message signed by a TSIG?
     * 
     * @see TSIG
     */
    public boolean isSigned() {
        return tsigState == TSIG_SIGNED || tsigState == TSIG_VERIFIED
               || tsigState == TSIG_FAILED;
    }

    /**
     * If this message was signed by a TSIG, was the TSIG verified?
     * 
     * @see TSIG
     */
    public boolean isVerified() {
        return tsigState == TSIG_VERIFIED;
    }

    /**
     * Returns the size of the message. Only valid if the message has been
     * converted to or from wire format.
     */
    public int numBytes() {
        return size;
    }

    /**
     * Removes all records from a section of the Message, and adjusts the
     * header.
     * 
     * @see Record
     * @see Section
     */
    public void removeAllRecords(int section) {
        sections[section] = null;
        header.setCount(section, 0);
    }

    /**
     * Removes a record from a section of the Message, and adjusts the header.
     * 
     * @see Record
     * @see Section
     */
    public boolean removeRecord(Record r, int section) {
        if (sections[section] != null && sections[section].remove(r)) {
            header.decCount(section);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Converts the given section of the Message to a String.
     * 
     * @see Section
     */
    public String sectionToString(int i) {
        if (i > 3) {
            return null;
        }

        StringBuffer sb = new StringBuffer();

        Record[] records = getSectionArray(i);
        for (Record rec : records) {
            if (i == Section.QUESTION) {
                sb.append(";;\t" + rec.name);
                sb.append(", type = " + Type.string(rec.type));
                sb.append(", class = " + DClass.string(rec.dclass));
            } else {
                sb.append(rec);
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Replaces the Header with a new one.
     * 
     * @see Header
     */
    public void setHeader(Header h) {
        header = h;
    }

    /**
     * Sets the TSIG key and other necessary information to sign a message.
     * 
     * @param key
     *            The TSIG key.
     * @param error
     *            The value of the TSIG error field.
     * @param querytsig
     *            If this is a response, the TSIG from the request.
     */
    public void setTSIG(TSIG key, int error, TSIGRecord querytsig) {
        tsigkey = key;
        tsigerror = error;
        this.querytsig = querytsig;
    }

    /**
     * Converts the Message to a String.
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        OPTRecord opt = getOPT();
        if (opt != null) {
            sb.append(header.toStringWithRcode(getRcode()) + "\n");
        } else {
            sb.append(header + "\n");
        }
        if (isSigned()) {
            sb.append(";; TSIG ");
            if (isVerified()) {
                sb.append("ok");
            } else {
                sb.append("invalid");
            }
            sb.append('\n');
        }
        for (int i = 0; i < 4; i++) {
            if (header.getOpcode() != Opcode.UPDATE) {
                sb.append(";; " + Section.longString(i) + ":\n");
            } else {
                sb.append(";; " + Section.updString(i) + ":\n");
            }
            sb.append(sectionToString(i) + "\n");
        }
        sb.append(";; Message size: " + numBytes() + " bytes");
        return sb.toString();
    }

    /**
     * Returns an array containing the wire format representation of the
     * Message.
     */
    public byte[] toWire() {
        DNSOutput out = new DNSOutput();
        toWire(out);
        size = out.current();
        return out.toByteArray();
    }

    /**
     * Returns an array containing the wire format representation of the Message
     * with the specified maximum length. This will generate a truncated message
     * (with the TC bit) if the message doesn't fit, and will also sign the
     * message with the TSIG key set by a call to setTSIG(). This method may
     * return null if the message could not be rendered at all; this could
     * happen if maxLength is smaller than a DNS header, for example.
     * 
     * @param maxLength
     *            The maximum length of the message.
     * @return The wire format of the message, or null if the message could not
     *         be rendered into the specified length.
     * @see Flags
     * @see TSIG
     */
    public byte[] toWire(int maxLength) {
        DNSOutput out = new DNSOutput();
        toWire(out, maxLength);
        size = out.current();
        return out.toByteArray();
    }

    /* Returns the number of records not successfully rendered. */
    private int sectionToWire(DNSOutput out, int section, Compression c,
                              int maxLength) {
        int n = sections[section].size();
        int pos = out.current();
        int rendered = 0;
        Record lastrec = null;

        for (int i = 0; i < n; i++) {
            Record rec = sections[section].get(i);
            if (lastrec != null && !sameSet(rec, lastrec)) {
                pos = out.current();
                rendered = i;
            }
            lastrec = rec;
            rec.toWire(out, section, c);
            if (out.current() > maxLength) {
                out.jump(pos);
                return n - rendered;
            }
        }
        return 0;
    }

    /* Returns true if the message could be rendered. */
    private boolean toWire(DNSOutput out, int maxLength) {
        if (maxLength < Header.LENGTH) {
            return false;
        }

        Header newheader = null;

        int tempMaxLength = maxLength;
        if (tsigkey != null) {
            tempMaxLength -= tsigkey.recordLength();
        }

        int startpos = out.current();
        header.toWire(out);
        Compression c = new Compression();
        for (int i = 0; i < 4; i++) {
            int skipped;
            if (sections[i] == null) {
                continue;
            }
            skipped = sectionToWire(out, i, c, tempMaxLength);
            if (skipped != 0) {
                if (newheader == null) {
                    newheader = header.clone();
                }
                if (i != Section.ADDITIONAL) {
                    newheader.setFlag(Flags.TC);
                }
                int count = newheader.getCount(i);
                newheader.setCount(i, count - skipped);
                for (int j = i + 1; j < 4; j++) {
                    newheader.setCount(j, 0);
                }

                out.save();
                out.jump(startpos);
                newheader.toWire(out);
                out.restore();
                break;
            }
        }

        if (tsigkey != null) {
            TSIGRecord tsigrec = tsigkey.generate(this, out.toByteArray(),
                                                  tsigerror, querytsig);

            if (newheader == null) {
                newheader = header.clone();
            }
            tsigrec.toWire(out, Section.ADDITIONAL, c);
            newheader.incCount(Section.ADDITIONAL);

            out.save();
            out.jump(startpos);
            newheader.toWire(out);
            out.restore();
        }

        return true;
    }

    void toWire(DNSOutput out) {
        header.toWire(out);
        Compression c = new Compression();
        for (int i = 0; i < 4; i++) {
            if (sections[i] == null) {
                continue;
            }
            for (int j = 0; j < sections[i].size(); j++) {
                Record rec = sections[i].get(j);
                rec.toWire(out, i, c);
            }
        }
    }

}
