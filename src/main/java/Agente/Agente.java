package Agente;

import java.io.File;
import java.io.IOException;

import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.log.Log4jLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.TransportMappings;


public class Agente extends BaseAgent {

    static {
        LogFactory.setLogFactory(new Log4jLogFactory());
    }

    private String address;

    public Agente(String address) throws IOException {

        super(new File("conf.agent"), new File("bootCounter.agent"),
                new CommandProcessor(
                        new OctetString(MPv3.createLocalEngineID())));
        this.address = address;
    }


    @Override
    protected void registerManagedObjects() {
    }


    public void registerManagedObject(ManagedObject mo) {
        try {
            server.register(mo, null);
        } catch (DuplicateRegistrationException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void unregisterManagedObject(MOGroup moGroup) {
        moGroup.unregisterMOs(server, getContext(moGroup));
    }

    /*
     * Empty implementation
     */
    @Override
    protected void addNotificationTargets(SnmpTargetMIB targetMIB,
                                          SnmpNotificationMIB notificationMIB) {
    }

    @Override
    protected void addViews(VacmMIB vacm) {

        vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString(
                        "cpublic"), new OctetString("v1v2group"),
                StorageType.nonVolatile);

        vacm.addAccess(new OctetString("v1v2group"), new OctetString("public"),
                SecurityModel.SECURITY_MODEL_ANY, SecurityLevel.NOAUTH_NOPRIV,
                MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
                new OctetString("fullWriteView"), new OctetString(
                        "fullNotifyView"), StorageType.nonVolatile);

        vacm.addViewTreeFamily(new OctetString("fullReadView"), new OID("1.3"),
                new OctetString(), VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);
    }

    protected void addUsmUser(USM usm) {
    }

    protected void initTransportMappings() throws IOException {
        transportMappings = new TransportMapping[1];
        Address addr = GenericAddress.parse(address);
        TransportMapping tm = TransportMappings.getInstance()
                .createTransportMapping(addr);
        transportMappings[0] = tm;
    }

    /**
     * Start method invokes some initialization methods needed to
     * start the agent
     * @throws IOException
     */
    public void start() throws IOException {
        init();
        addShutdownHook();
        getServer().addContext(new OctetString("public"));
        finishInit();
        run();
        sendColdStartNotification();
    }



    protected void unregisterManagedObjects() {
    }


    protected void addCommunities(SnmpCommunityMIB communityMIB) {
        Variable[] com2sec = new Variable[] {
                new OctetString("public"), // community name
                new OctetString("cpublic"), // security name
                getAgent().getContextEngineID(), // local engine ID
                new OctetString("public"), // default context name
                new OctetString(), // transport tag
                new Integer32(StorageType.nonVolatile), // storage type
                new Integer32(RowStatus.active) // row status
        };
        MOTableRow row = communityMIB.getSnmpCommunityEntry().createRow(
                new OctetString("public2public").toSubIndex(true), com2sec);
        communityMIB.getSnmpCommunityEntry().addRow((SnmpCommunityMIB.SnmpCommunityEntryRow) row);
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        Agente agent = new Agente("0.0.0.0/2001");

        OID interfacesTable = new OID(".1.3.6.1.2.1.2.2.1");

        MOTableBuilder builder = new MOTableBuilder(interfacesTable)
                .addColumnType(SMIConstants.SYNTAX_INTEGER, MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_OCTET_STRING,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_GAUGE32,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_OCTET_STRING,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                // Normally you would begin loop over you two domain objects here
                .addRowValue(new Integer32(1))
                .addRowValue(new OctetString("loopback"))
                .addRowValue(new Integer32(24))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Gauge32(10000000))
                .addRowValue(new OctetString("00:00:00:00:01"))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Integer32(1500))
                //next row
                .addRowValue(new Integer32(2))
                .addRowValue(new OctetString("eth0"))
                .addRowValue(new Integer32(24))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Gauge32(10000000))
                .addRowValue(new OctetString("00:00:00:00:02"))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Integer32(1500));

        agent.registerManagedObject(builder.build());

        agent.start();
        while(true) {
            System.out.println("Agent is running...");
            Thread.sleep(5000);
        }
    }
}
