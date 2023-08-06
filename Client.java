import java.util.List;
import java.util.ArrayList;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TTransportFactory;

class Requestor extends Thread{
	String host;
	String port;
	List<String> password;
	static int global_count = 0;
	int count;
	public Requestor(String host, String port, List<String> password){
		this.host =host;
		this.port =port;
		this.password = password;
		count = global_count;
		global_count +=1;
	}
	public void run(){
		
		try {
			TSocket sock = new TSocket(host, Integer.parseInt(port));
			TTransport transport = new TFramedTransport(sock);
			TProtocol protocol = new TBinaryProtocol(transport);
			BcryptService.Client client = new BcryptService.Client(protocol);
			transport.open();

			int password_epoch = 2;
			for (int i = 0;i<password_epoch;i++){

				long start = System.currentTimeMillis();
				System.out.println(i+" "+count+" starting");
				List<String> hash = client.hashPassword(password, (short)10);
				System.out.println(i+" "+count+" Password: " + password.get(0));

				long hash_time = System.currentTimeMillis();
				System.out.println(i+" "+count+" Positive check: " + client.checkPassword(password, hash));
				
				long check_time = System.currentTimeMillis();
				System.out.println(i+" "+count+" hash time: "+(hash_time-start)+"ms, check time: "+(check_time-hash_time)+"ms");
				System.out.println(i+" "+count+" total time for password "+i+": " +(System.currentTimeMillis()-start)+"ms");
				/*
				System.out.println("Hash: " + hash.get(0))
				
				hash.set(0, "$2a$14$reBHJvwbb0UWqJHLyPTVF.6Ld5sFRirZx/bXMeMmeurJledKYdZmG");
				System.out.println("Negative check: " + client.checkPassword(password, hash));
				*/
				/*
				try {
					hash.set(0, "too short");
					List<Boolean> rets = client.checkPassword(password, hash);
					System.out.println("Exception check: no exception thrown");
				} catch (Exception e) {
					System.out.println("Exception check: exception thrown");
				}
				*/
			}
			transport.close();
		} catch (TException x) {
			x.printStackTrace();
		} 
	}
}
public class Client {
	public static void main(String [] args) {
		if (args.length != 3) {
			System.err.println("Usage: java Client FE_host FE_port password");
			System.exit(-1);
		}
		int password_num = 4;
		List<Requestor> arr = new ArrayList<>();
		List<String> pwds = new ArrayList<>();
		for (int i = 0;i<password_num;i++)
			pwds.add(args[2]+i);
		long start = System.currentTimeMillis();
		for (int i = 0;i<10;i++){
			arr.add(new Requestor(args[0],args[1],pwds));
			arr.get(arr.size()-1).start();
		}
		
		try{
		for (Requestor r : arr){
			r.join();
		}
		}catch(InterruptedException e){}
		
		System.out.println("total time: "+(System.currentTimeMillis()-start)+"ms");
	}
}
