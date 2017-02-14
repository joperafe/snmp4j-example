package Gestor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableUtils;


public class Gestor {

    private String address;
    private Snmp snmp;


    public Gestor(String address) {
        super();
        this.address = address;
        try {
            start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() throws IOException {
        snmp.close();
    }

    private void start() throws IOException {
        TransportMapping transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        //ficar à escuta de respostas (a chegada das mensagens é assincrona)
        transport.listen();
    }

    public String getAsString(OID oid) throws IOException {
        ResponseEvent event = get(new OID[]{oid});
        return event.getResponse().get(0).getVariable().toString();
    }


    public void getAsString(OID oids,ResponseListener listener) {
        try {
            snmp.send(getPDU(new OID[]{oids}), getTarget(),null, listener);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public ResponseEvent request(PDU pdu) throws IOException {
        ResponseEvent event = snmp.send(pdu, getTarget(), null);
        if(event != null) {
            System.out.println("response-status = "+ event.getResponse().getErrorStatus());
            return event;
        }
        throw new RuntimeException("GET timed out");
    }

    public String sendRequest(PDU pdu) throws IOException {
        ResponseEvent event = request(pdu);
        return event.getResponse().get(0).getVariable().toString();
    }


    private PDU getPDU(OID oids[]) {
        PDU pdu = new PDU();
        for (OID oid : oids) {
            pdu.add(new VariableBinding(oid));
        }

        pdu.setType(PDU.GET);
        return pdu;
    }

    public ResponseEvent get(OID oids[]) throws IOException {
        ResponseEvent event = snmp.send(getPDU(oids), getTarget(), null);
        if(event != null) {
            return event;
        }
        throw new RuntimeException("GET timed out");
    }

    private Target getTarget() {
        Address targetAddress = GenericAddress.parse(address);
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);
        return target;
    }

    public List<List<String>> getTableAsStrings(OID[] oids) {
        TableUtils tUtils = new TableUtils(snmp, new DefaultPDUFactory());

        @SuppressWarnings("unchecked")
        List<TableEvent> events = tUtils.getTable(getTarget(), oids, null, null);

        List<List<String>> list = new ArrayList<List<String>>();
        for (TableEvent event : events) {
            if(event.isError()) {
                throw new RuntimeException(event.getErrorMessage());
            }
            List<String> strList = new ArrayList<String>();
            list.add(strList);
            for(VariableBinding vb: event.getColumns()) {
                strList.add(vb.getVariable().toString());
            }
        }
        return list;
    }

    public static String extractSingleString(ResponseEvent event) {
        return event.getResponse().get(0).getVariable().toString();
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        Gestor gestor = new Gestor("udp:127.0.0.1/2001");
        OID sysDescr = new OID(".1.3.6.1.2.1.1.1.0");
        OID interfacesTable = new OID(".1.3.6.1.2.1.2.2.1");

        String res;
        for (int i=1; i<8; i++){
            res = gestor.getAsString(new OID(".1.3.6.1.2.1.1."+i+".0"));
            System.out.println("{.1.3.6.1.2.1.1."+i+".0} -> "+ res);
        }

        OID oid = new OID( ".1.3.6.1.2.1.2.2.1" );
        PDU pdu = new PDU () ;
        pdu.add (new VariableBinding( oid ) ) ;
        pdu.setType(PDU.GETNEXT);
        res = gestor.sendRequest(pdu);
        System.out.println("getnext{"+oid.toString()+"} -> "+ res);

        List<List<String>> tableContents = gestor.getTableAsStrings(new OID[]{
                new OID(interfacesTable.toString() + ".2"),
                new OID(interfacesTable.toString() + ".6"),
                new OID(interfacesTable.toString() + ".8")});

        System.out.println("getnext{"+oid.toString()+"} -> "+ tableContents);


    }

}
