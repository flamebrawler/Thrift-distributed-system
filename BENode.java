import java.net.InetAddress;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import org.apache.thrift.*;
import org.apache.thrift.server.*;
import org.apache.thrift.server.TServer.*;
import org.apache.thrift.protocol.*;
import org.apache.thrift.transport.*;
import java.util.concurrent.TimeUnit;


public class BENode {
	static Logger log;

	public static void main(String [] args) throws Exception {
		if (args.length != 3) {
			System.err.println("Usage: java BENode FE_host FE_port BE_port");
			System.exit(-1);
		}

		// initialize log4j
		BasicConfigurator.configure();
		log = Logger.getLogger(BENode.class.getName());

		String hostFE = args[0];
		int portFE = Integer.parseInt(args[1]);
		int portBE = Integer.parseInt(args[2]);
		log.info("Launching BE node on port " + portBE + " at host " + getHostName());

		// launch Thrift server
		BcryptService.Processor processor = new BcryptService.Processor<BcryptService.Iface>(new BcryptServiceHandler());
		TNonblockingServerSocket socket = new TNonblockingServerSocket(portBE);
		THsHaServer.Args sargs = new THsHaServer.Args(socket);
		sargs.protocolFactory(new TBinaryProtocol.Factory());
		sargs.transportFactory(new TFramedTransport.Factory());
		sargs.processorFactory(new TProcessorFactory(processor));
		sargs.maxWorkerThreads(5);
		TServer server = new THsHaServer(sargs);

		boolean success = false;
		while(!success){	
			try{
				TSocket sock = new TSocket(hostFE, portFE);
				TTransport transport = new TFramedTransport(sock);
				TProtocol protocol = new TBinaryProtocol(transport);
				BcryptService.Client client = new BcryptService.Client(protocol);
				transport.open();
				client.connect(InetAddress.getLocalHost().getHostName(),portBE);
				transport.close();
				success= true;
			}catch(Exception e){
				//don't try too many connections
				System.out.println("failed to connect...");
				TimeUnit.SECONDS.sleep(1);	
			}
		}
		server.serve();
	}

	static String getHostName()
	{
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (Exception e) {
			return "localhost";
		}
	}
}
