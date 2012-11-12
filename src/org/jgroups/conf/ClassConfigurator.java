
package org.jgroups.conf;


import org.jgroups.Address;
import org.jgroups.Global;
import org.jgroups.logging.Log;
import org.jgroups.logging.LogFactory;
import org.jgroups.util.Tuple;
import org.jgroups.util.Util;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

/**
 * This class will be replaced with the class that read info
 * from the magic number configurator that reads info from the xml file.
 * The name and the relative path of the magic number map file can be specified
 * as value of the property <code>org.jgroups.conf.magicNumberFile</code>.
 * It must be relative to one of the classpath elements, to allow the
 * classloader to locate the file. If a value is not specified,
 * <code>MagicNumberReader.MAGIC_NUMBER_FILE</code> is used, which defaults
 * to "jg-magic-map.xml".
 *
 * @author Filip Hanik
 * @author Bela Ban
 */
public class ClassConfigurator {
    private static final int   MAX_MAGIC_VALUE=150;
    private static final short MIN_CUSTOM_MAGIC_NUMBER=1024;
    private static final short MIN_CUSTOM_PROTOCOL_ID=512;

    // this is where we store magic numbers; contains data from jg-magic-map.xml;  key=Class, value=magic number
    private static final Map<Class,Short> classMap=new IdentityHashMap<Class,Short>(MAX_MAGIC_VALUE);


    // Magic map for all values defined in jg-magic-map.xml
    private static final Class[] magicMap=new Class[MAX_MAGIC_VALUE]; /// simple array, IDs are the indices

    // Magic map for user-defined IDs / classes
    private static final Map<Short,Class> magicMapUser=new HashMap<Short,Class>(); // key=magic number, value=Class

    /** Contains data read from jg-protocol-ids.xml */
    private static final Map<Class,Short> protocol_ids=new HashMap<Class,Short>(MAX_MAGIC_VALUE);
    private static final Map<Short,Class> protocol_names=new HashMap<Short,Class>(MAX_MAGIC_VALUE);

    protected static final Log log=LogFactory.getLog(ClassConfigurator.class);


    static {
        try {
            init();
        }
        catch(Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public ClassConfigurator() {
    }

    protected static void init() throws Exception {
        // make sure we have a class for DocumentBuilderFactory
        Util.loadClass("javax.xml.parsers.DocumentBuilderFactory", ClassConfigurator.class);

        // Read jg-magic-map.xml - Now hard-coded here
        List<Tuple<Short,String>> mappingMagicMap = new LinkedList<Tuple<Short,String>>();
        mappingMagicMap.add(new Tuple<Short,String>((short)1, "org.jgroups.stack.IpAddress"));
        mappingMagicMap.add(new Tuple<Short,String>((short)3, "org.jgroups.protocols.FD$FdHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)6, "org.jgroups.protocols.FD_SOCK$FdHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)7, "org.jgroups.protocols.FragHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)13, "org.jgroups.protocols.PingHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)21, "org.jgroups.protocols.UNICAST$UnicastHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)22, "org.jgroups.protocols.VERIFY_SUSPECT$VerifyHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)24, "org.jgroups.protocols.pbcast.GMS$GmsHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)25, "org.jgroups.protocols.pbcast.NakAckHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)27, "org.jgroups.protocols.pbcast.STABLE$StableHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)28, "org.jgroups.protocols.pbcast.STATE_TRANSFER$StateHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)30, "org.jgroups.Message"));
        mappingMagicMap.add(new Tuple<Short,String>((short)31, "org.jgroups.View"));
        mappingMagicMap.add(new Tuple<Short,String>((short)32, "org.jgroups.ViewId"));
        mappingMagicMap.add(new Tuple<Short,String>((short)34, "org.jgroups.Address"));
        mappingMagicMap.add(new Tuple<Short,String>((short)36, "org.jgroups.protocols.PingData"));
        mappingMagicMap.add(new Tuple<Short,String>((short)38, "java.util.Vector"));
        mappingMagicMap.add(new Tuple<Short,String>((short)39, "org.jgroups.protocols.pbcast.JoinRsp"));
        mappingMagicMap.add(new Tuple<Short,String>((short)40, "org.jgroups.util.Digest"));
        mappingMagicMap.add(new Tuple<Short,String>((short)41, "java.util.Hashtable"));
        mappingMagicMap.add(new Tuple<Short,String>((short)53, "org.jgroups.protocols.COMPRESS$CompressHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)54, "org.jgroups.protocols.FcHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)56, "org.jgroups.protocols.TpHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)57, "org.jgroups.protocols.ENCRYPT$EncryptHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)58, "org.jgroups.protocols.SEQUENCER$SequencerHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)59, "org.jgroups.protocols.FD_SIMPLE$FdHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)61, "org.jgroups.protocols.FD_ALL$HeartbeatHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)64, "org.jgroups.protocols.pbcast.FLUSH$FlushHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)65, "org.jgroups.protocols.pbcast.StreamingStateTransfer$StateHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)67, "org.jgroups.protocols.AuthHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)68, "org.jgroups.util.UUID"));
        mappingMagicMap.add(new Tuple<Short,String>((short)71, "org.jgroups.blocks.RequestCorrelator$Header"));
        mappingMagicMap.add(new Tuple<Short,String>((short)72, "org.jgroups.blocks.RequestCorrelator$MultiDestinationHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)73, "org.jgroups.protocols.UNICAST2$Unicast2Header"));
        mappingMagicMap.add(new Tuple<Short,String>((short)74, "org.jgroups.protocols.SCOPE$ScopeHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)75, "org.jgroups.blocks.mux.MuxHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)76, "org.jgroups.protocols.DAISYCHAIN$DaisyHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)77, "org.jgroups.protocols.RELAY$RelayHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)78, "org.jgroups.protocols.STOMP$StompHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)80, "org.jgroups.protocols.PrioHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)81, "org.jgroups.protocols.Locking$LockingHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)82, "org.jgroups.util.PayloadUUID"));
        mappingMagicMap.add(new Tuple<Short,String>((short)83, "org.jgroups.util.AdditionalDataUUID"));
        mappingMagicMap.add(new Tuple<Short,String>((short)84, "org.jgroups.util.TopologyUUID"));
        mappingMagicMap.add(new Tuple<Short,String>((short)85, "org.jgroups.protocols.Executing$ExecutorHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)86, "org.jgroups.protocols.Executing$Request"));
        mappingMagicMap.add(new Tuple<Short,String>((short)87, "org.jgroups.blocks.executor.ExecutionService$RunnableAdapter"));
        mappingMagicMap.add(new Tuple<Short,String>((short)88, "org.jgroups.blocks.executor.Executions$StreamableCallable"));
        mappingMagicMap.add(new Tuple<Short,String>((short)89, "org.jgroups.protocols.COUNTER$CounterHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)90, "org.jgroups.protocols.MERGE3$MergeHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)91, "org.jgroups.protocols.RSVP$RsvpHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)93, "org.jgroups.protocols.pbcast.NakAckHeader2"));
        mappingMagicMap.add(new Tuple<Short,String>((short)94, "org.jgroups.util.SeqnoList"));
        mappingMagicMap.add(new Tuple<Short,String>((short)95, "org.jgroups.protocols.tom.ToaHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)96, "org.jgroups.AnycastAddress"));
        mappingMagicMap.add(new Tuple<Short,String>((short)97, "org.jgroups.protocols.relay.SiteUUID"));
        mappingMagicMap.add(new Tuple<Short,String>((short)98, "org.jgroups.protocols.relay.SiteMaster"));
        mappingMagicMap.add(new Tuple<Short,String>((short)99, "org.jgroups.protocols.relay.RELAY2$Relay2Header"));
        mappingMagicMap.add(new Tuple<Short,String>((short)100, "org.jgroups.protocols.FORWARD_TO_COORD$ForwardHeader"));
        mappingMagicMap.add(new Tuple<Short,String>((short)101, "org.jgroups.protocols.relay.CanBeSiteMaster"));
        mappingMagicMap.add(new Tuple<Short,String>((short)102, "org.jgroups.protocols.relay.CanBeSiteMasterTopology"));
        for(Tuple<Short,String> tuple: mappingMagicMap) {
            short m=tuple.getVal1();
            if(m >= MAX_MAGIC_VALUE)
                throw new IllegalArgumentException("ID " + m + " is bigger than MAX_MAGIC_VALUE (" +
                                                     MAX_MAGIC_VALUE + "); increase MAX_MAGIC_VALUE");
            Class clazz=Util.loadClass(tuple.getVal2(), ClassConfigurator.class);
            if(magicMap[m] != null)
                throw new Exception("key " + m + " (" + clazz.getName() + ')' +
                                      " is already in magic map; please make sure that all keys are unique");
            magicMap[m]=clazz;
            classMap.put(clazz, m);
        }

        // Read jg-protocol-ids.xml, now hard-coded
        List<Tuple<Short,String>> mappingProtocol = new LinkedList<Tuple<Short,String>>();
        mappingProtocol.add(new Tuple<Short,String>((short)2, "org.jgroups.protocols.FD"));
        mappingProtocol.add(new Tuple<Short,String>((short)3, "org.jgroups.protocols.FD_SOCK"));
        mappingProtocol.add(new Tuple<Short,String>((short)4, "org.jgroups.protocols.FRAG"));
        mappingProtocol.add(new Tuple<Short,String>((short)5, "org.jgroups.protocols.FRAG2"));
        mappingProtocol.add(new Tuple<Short,String>((short)6, "org.jgroups.protocols.PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)7, "org.jgroups.protocols.MPING"));
        mappingProtocol.add(new Tuple<Short,String>((short)8, "org.jgroups.protocols.S3_PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)9, "org.jgroups.protocols.FILE_PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)10, "org.jgroups.protocols.TCPPING"));
        mappingProtocol.add(new Tuple<Short,String>((short)11, "org.jgroups.protocols.TCPGOSSIP"));
        mappingProtocol.add(new Tuple<Short,String>((short)12, "org.jgroups.protocols.UNICAST"));
        mappingProtocol.add(new Tuple<Short,String>((short)13, "org.jgroups.protocols.VERIFY_SUSPECT"));
        mappingProtocol.add(new Tuple<Short,String>((short)14, "org.jgroups.protocols.pbcast.GMS"));
        mappingProtocol.add(new Tuple<Short,String>((short)15, "org.jgroups.protocols.pbcast.NAKACK"));
        mappingProtocol.add(new Tuple<Short,String>((short)16, "org.jgroups.protocols.pbcast.STABLE"));
        mappingProtocol.add(new Tuple<Short,String>((short)17, "org.jgroups.protocols.pbcast.STATE_TRANSFER"));
        mappingProtocol.add(new Tuple<Short,String>((short)19, "org.jgroups.protocols.COMPRESS"));
        mappingProtocol.add(new Tuple<Short,String>((short)20, "org.jgroups.protocols.FC"));
        mappingProtocol.add(new Tuple<Short,String>((short)21, "org.jgroups.protocols.UDP"));
        mappingProtocol.add(new Tuple<Short,String>((short)22, "org.jgroups.protocols.TCP"));
        mappingProtocol.add(new Tuple<Short,String>((short)23, "org.jgroups.protocols.TCP_NIO"));
        mappingProtocol.add(new Tuple<Short,String>((short)24, "org.jgroups.protocols.TUNNEL"));
        mappingProtocol.add(new Tuple<Short,String>((short)25, "org.jgroups.protocols.ENCRYPT"));
        mappingProtocol.add(new Tuple<Short,String>((short)26, "org.jgroups.protocols.SEQUENCER"));
        mappingProtocol.add(new Tuple<Short,String>((short)27, "org.jgroups.protocols.FD_SIMPLE"));
        mappingProtocol.add(new Tuple<Short,String>((short)28, "org.jgroups.protocols.FD_ICMP"));
        mappingProtocol.add(new Tuple<Short,String>((short)29, "org.jgroups.protocols.FD_ALL"));
        mappingProtocol.add(new Tuple<Short,String>((short)31, "org.jgroups.protocols.pbcast.FLUSH"));
        mappingProtocol.add(new Tuple<Short,String>((short)33, "org.jgroups.protocols.AUTH"));
        mappingProtocol.add(new Tuple<Short,String>((short)34, "org.jgroups.protocols.pbcast.STATE"));
        mappingProtocol.add(new Tuple<Short,String>((short)35, "org.jgroups.protocols.pbcast.STATE_SOCK"));
        mappingProtocol.add(new Tuple<Short,String>((short)36, "org.jgroups.protocols.HTOTAL"));
        mappingProtocol.add(new Tuple<Short,String>((short)37, "org.jgroups.protocols.DISCARD"));
        mappingProtocol.add(new Tuple<Short,String>((short)39, "org.jgroups.protocols.SHARED_LOOPBACK"));
        mappingProtocol.add(new Tuple<Short,String>((short)40, "org.jgroups.protocols.UNICAST2"));
        mappingProtocol.add(new Tuple<Short,String>((short)41, "org.jgroups.protocols.SCOPE"));
        mappingProtocol.add(new Tuple<Short,String>((short)42, "org.jgroups.protocols.DAISYCHAIN"));
        mappingProtocol.add(new Tuple<Short,String>((short)43, "org.jgroups.protocols.RELAY"));
        mappingProtocol.add(new Tuple<Short,String>((short)44, "org.jgroups.protocols.MFC"));
        mappingProtocol.add(new Tuple<Short,String>((short)45, "org.jgroups.protocols.UFC"));
        mappingProtocol.add(new Tuple<Short,String>((short)46, "org.jgroups.protocols.JDBC_PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)47, "org.jgroups.protocols.STOMP"));
        mappingProtocol.add(new Tuple<Short,String>((short)48, "org.jgroups.protocols.PRIO"));
        mappingProtocol.add(new Tuple<Short,String>((short)49, "org.jgroups.protocols.BPING"));
        mappingProtocol.add(new Tuple<Short,String>((short)50, "org.jgroups.protocols.CENTRAL_LOCK"));
        mappingProtocol.add(new Tuple<Short,String>((short)51, "org.jgroups.protocols.PEER_LOCK"));
        mappingProtocol.add(new Tuple<Short,String>((short)52, "org.jgroups.protocols.CENTRAL_EXECUTOR"));
        mappingProtocol.add(new Tuple<Short,String>((short)53, "org.jgroups.protocols.COUNTER"));
        mappingProtocol.add(new Tuple<Short,String>((short)54, "org.jgroups.protocols.MERGE3"));
        mappingProtocol.add(new Tuple<Short,String>((short)55, "org.jgroups.protocols.RSVP"));
        mappingProtocol.add(new Tuple<Short,String>((short)56, "org.jgroups.protocols.RACKSPACE_PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)57, "org.jgroups.protocols.pbcast.NAKACK2"));
        mappingProtocol.add(new Tuple<Short,String>((short)58, "org.jgroups.protocols.tom.TOA"));
        mappingProtocol.add(new Tuple<Short,String>((short)59, "org.jgroups.protocols.SWIFT_PING"));
        mappingProtocol.add(new Tuple<Short,String>((short)60, "org.jgroups.protocols.relay.RELAY2"));
        mappingProtocol.add(new Tuple<Short,String>((short)61, "org.jgroups.protocols.FORWARD_TO_COORD"));
        mappingProtocol.add(new Tuple<Short,String>((short)200, "org.jgroups.blocks.RequestCorrelator"));
        mappingProtocol.add(new Tuple<Short,String>((short)201, "org.jgroups.blocks.mux.MuxRequestCorrelator"));
        for(Tuple<Short,String> tuple: mappingProtocol) {
            short m=tuple.getVal1();
            Class clazz=Util.loadClass(tuple.getVal2(), ClassConfigurator.class);
            if(protocol_ids.containsKey(clazz))
                throw new Exception("ID " + m + " (" + clazz.getName() + ')' +
                                      " is already in protocol-id map; make sure that all protocol IDs are unique");
            protocol_ids.put(clazz, m);
            protocol_names.put(m, clazz);
        }
    }



    /**
     * Method to register a user-defined header with jg-magic-map at runtime
     * @param magic The magic number. Needs to be > 1024
     * @param clazz The class. Usually a subclass of Header
     * @throws IllegalArgumentException If the magic number is already taken, or the magic number is <= 1024
     */
    public static void add(short magic, Class clazz) throws IllegalArgumentException {
        if(magic < MIN_CUSTOM_MAGIC_NUMBER)
            throw new IllegalArgumentException("magic number (" + magic + ") needs to be greater than " +
                                                 MIN_CUSTOM_MAGIC_NUMBER);
        if(magicMapUser.containsKey(magic))
            throw new IllegalArgumentException("magic number " + magic + " for class " + clazz.getName() +
                                                 " is already present");
        if(classMap.containsKey(clazz))
            throw new IllegalArgumentException("class " + clazz.getName() + " is already present");
        magicMapUser.put(magic, clazz);
        classMap.put(clazz, magic);
    }


    public static void addProtocol(short id, Class protocol) {
        if(id <= MIN_CUSTOM_PROTOCOL_ID)
            throw new IllegalArgumentException("protocol ID (" + id + ") needs to be greater than " + MIN_CUSTOM_PROTOCOL_ID);
        if(protocol_ids.containsKey(protocol))
            throw new IllegalArgumentException("Protocol " + protocol + " is already present");
        protocol_ids.put(protocol, id);
    }


    /**
     * Returns a class for a magic number.
     * Returns null if no class is found
     *
     * @param magic the magic number that maps to the class
     * @return a Class object that represents a class that implements java.io.Externalizable
     */
    public static Class<Address> get(short magic) {
        return magic < MIN_CUSTOM_MAGIC_NUMBER? magicMap[magic] : magicMapUser.get(magic);
    }

    /**
     * Loads and returns the class from the class name
     *
     * @param clazzname a fully classified class name to be loaded
     * @return a Class object that represents a class that implements java.io.Externalizable
     */
    public static Class get(String clazzname) {
        try {
            // return ClassConfigurator.class.getClassLoader().loadClass(clazzname);
            return Util.loadClass(clazzname, ClassConfigurator.class);
        }
        catch(Exception x) {
            if(log.isErrorEnabled()) log.error("failed loading class " + clazzname, x);
        }
        return null;
    }

    /**
     * Returns the magic number for the class.
     *
     * @param clazz a class object that we want the magic number for
     * @return the magic number for a class, -1 if no mapping is available
     */
    public static short getMagicNumber(Class clazz) {
        Short i=classMap.get(clazz);
        if(i == null)
            return -1;
        else
            return i;
    }


    public static short getProtocolId(Class protocol) {
        Short retval=protocol_ids.get(protocol);
        if(retval != null)
            return retval;
        return 0;
    }


    public static Class getProtocol(short id) {
        return protocol_names.get(id);
    }


    public String toString() {
        return printMagicMap();
    }

    public static String printMagicMap() {
        StringBuilder sb=new StringBuilder();
        SortedSet<Short> keys=new TreeSet<Short>(magicMapUser.keySet());
        for(short i=0; i < magicMap.length; i++) {
            if(magicMap[i] != null)
                keys.add(i);
        }

        for(Short key: keys) {
            sb.append(key).append(":\t").append(key < MIN_CUSTOM_MAGIC_NUMBER? magicMap[key] : magicMapUser.get(key)).append('\n');
        }
        return sb.toString();
    }

    public static String printClassMap() {
        StringBuilder sb=new StringBuilder();
        Map.Entry entry;

        for(Iterator it=classMap.entrySet().iterator(); it.hasNext();) {
            entry=(Map.Entry)it.next();
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
        }
        return sb.toString();
    }


}
