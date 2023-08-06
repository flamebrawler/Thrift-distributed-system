import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Arrays;

import org.mindrot.jbcrypt.BCrypt;
import org.apache.thrift.async.*;
import org.apache.thrift.protocol.*;
import org.apache.thrift.transport.*;
import org.apache.thrift.server.*;

public class BcryptServiceHandler implements BcryptService.Iface {

	private static final int FE_NODE_ID = 0;
	private static final int BE1_NODE_ID = 1;
	private static final int BE2_NODE_ID = 2;

	static String BE1_HOST;
	static int BE1_PORT;
	static String BE2_HOST;
	static int BE2_PORT;


	static List<BcryptService.AsyncClient> backends = new ArrayList<>();
	static PriorityBlockingQueue<WorkerNode> loadQueue = new PriorityBlockingQueue<WorkerNode>(3, (WorkerNode n1, WorkerNode n2) -> Integer.compare(n1.getLoad(), n2.getLoad()));

	static TProtocolFactory protocolFactory;                                                      
	static TAsyncClientManager clientManager;
	
	BcryptServiceHandler(){
		loadQueue.add(new WorkerNode(FE_NODE_ID));
		protocolFactory = new TBinaryProtocol.Factory();
		try{
			clientManager = new TAsyncClientManager();
		} catch(Exception e){
			System.out.println(e.getMessage());
		}
	}

	private List<String> computeHash(List<String> password, short logrounds){

		List<String> ret = new ArrayList<>();
		for (String pwd : password){
			String oneHash = BCrypt.hashpw(pwd, BCrypt.gensalt(logrounds));
			ret.add(oneHash);
		}
		return ret;
	}

	private List<Boolean> computeCheck(List<String> password, List<String> hash) throws IllegalArgumentException{
		if (password.size()!= hash.size())
			throw new IllegalArgumentException("password and hash for check not of same length");
		List<Boolean> ret = new ArrayList<>();
		for (int i = 0;i<password.size();i++){
			ret.add(BCrypt.checkpw(password.get(i), hash.get(i)));
		}
		return ret;
	}

	
	public List<String> hashPassword(List<String> password, short logRounds) throws IllegalArgument, org.apache.thrift.TException
	{
		System.out.println("hashing passwords "+password.size());
		try {
			String[] outputs = new String[password.size()];

			WorkerNode bestNode = loadQueue.take();
			int originalLoad = bestNode.getLoad();
			bestNode.setLoad(originalLoad + password.size());
			System.out.println("bestNode: " + bestNode.printNodeName());
			System.out.println("bestNode load: " + originalLoad + " + " + password.size());

			if (bestNode.id == FE_NODE_ID) {
				try {
					List<String> result = computeHash(password,logRounds);
					int oldload = bestNode.getLoad();
					bestNode.setLoad(oldload - password.size());
					loadQueue.add(bestNode);
					System.out.println("hashPassword delegated to FE");
					return result;
				} catch(IllegalArgumentException e) {
					throw new IllegalArgumentException(e.getMessage());
				}
			}
			CountDownLatch latch = new CountDownLatch(1);
			if (bestNode.id == BE1_NODE_ID) {
				try {
					TNonblockingTransport transport = new TNonblockingSocket(BE1_HOST, BE1_PORT);                          
					BcryptService.AsyncClient client = new BcryptService.AsyncClient(protocolFactory, clientManager, transport);  
					ServerCallback<String> cb = new ServerCallback<String>(latch,outputs,0);
					client.delegatePasswordHash(password, logRounds, cb);
				} catch (Exception e) {
					throw new IllegalArgument(e.getMessage());
				}
			}
			else if (bestNode.id == BE2_NODE_ID) {
				try {
					TNonblockingTransport transport = new TNonblockingSocket(BE2_HOST, BE2_PORT);                          
					BcryptService.AsyncClient client = new BcryptService.AsyncClient(protocolFactory, clientManager, transport);  
					ServerCallback<String> cb = new ServerCallback<String>(latch,outputs,0);
					client.delegatePasswordHash(password, logRounds, cb);
				} catch (Exception e) {
					throw new IllegalArgument(e.getMessage());
				}
			}

			latch.await();
			int oldload = bestNode.getLoad();
			bestNode.setLoad(oldload - password.size());
			loadQueue.add(bestNode);
			System.out.println("output1: "+outputs[0]);
			return Arrays.asList(outputs);	
		} catch (Exception e) {
			throw new IllegalArgument(e.getMessage());
		}
	}

	public List<Boolean> checkPassword(List<String> password, List<String> hash) throws IllegalArgument, org.apache.thrift.TException
	{
		System.out.println("checking passwords "+password.size());
		try {
			Boolean outputs[] = new Boolean[password.size()];

			WorkerNode bestNode = loadQueue.take();
			int originalLoad = bestNode.getLoad();
			bestNode.setLoad(originalLoad + password.size());
			System.out.println("bestNode: " + bestNode.printNodeName());
			System.out.println("bestNode load: " + originalLoad + " + " + password.size());

			if (bestNode.id == FE_NODE_ID) {
				try {
					List<Boolean> result = computeCheck(password, hash);
					int oldload = bestNode.getLoad();
					bestNode.setLoad(oldload - password.size());
					loadQueue.add(bestNode);
					System.out.println("hashPassword delegated to FE");
					return result;
				} catch(IllegalArgumentException e) {
					throw new IllegalArgumentException(e.getMessage());
				}
			}
			CountDownLatch latch = new CountDownLatch(1);
			if (bestNode.id == BE1_NODE_ID) {
				try {
					TNonblockingTransport transport = new TNonblockingSocket(BE1_HOST, BE1_PORT);                          
					BcryptService.AsyncClient client = new BcryptService.AsyncClient(protocolFactory, clientManager, transport);  
					ServerCallback<Boolean> cb = new ServerCallback<Boolean>(latch,outputs,0);
					client.delegatePasswordCheck(password, hash, cb);
				} catch (Exception e) {
					throw new IllegalArgument(e.getMessage());
				}
			}
			else if (bestNode.id == BE2_NODE_ID) {
				try {
					TNonblockingTransport transport = new TNonblockingSocket(BE2_HOST, BE2_PORT);                          
					BcryptService.AsyncClient client = new BcryptService.AsyncClient(protocolFactory, clientManager, transport);  
					ServerCallback<Boolean> cb = new ServerCallback<Boolean>(latch,outputs,0);
					client.delegatePasswordCheck(password, hash, cb);
				} catch (Exception e) {
					throw new IllegalArgument(e.getMessage());
				}
			}

			latch.await();
			int oldload = bestNode.getLoad();
			bestNode.setLoad(oldload - password.size());
			loadQueue.add(bestNode);
			System.out.println("output1: "+outputs[0]);
			return Arrays.asList(outputs);	
		} catch (Exception e) {
			throw new IllegalArgument(e.getMessage());
		}
	}
	class ServerCallback<V> implements AsyncMethodCallback<List<V>> {
		private CountDownLatch latch;
		private V[]responses;
		private int start;

        public ServerCallback (CountDownLatch latch,V[] responses,int start) {
			this.latch = latch;
			this.responses = responses;
			this.start = start;
        }

        public void onComplete(List<V> resp) {
			for (int i = 0;i<resp.size();i++){
				responses[i+start] = resp.get(i);
			}
            latch.countDown();
        }


        public void onError(Exception e) {
            e.printStackTrace();
            latch.countDown();
        }
    }
    public void connect(String host, int port) throws org.apache.thrift.TException {
			System.out.println("connecting from "+host+ " at port "+port);
			if (loadQueue.size() == 1) { //adding 1st BE node
				loadQueue.add(new WorkerNode(BE1_NODE_ID));
				BE1_HOST = host;
				BE1_PORT = port;
			}
			else if (loadQueue.size() == 2) { //adding 2nd BE node
				loadQueue.add(new WorkerNode(BE2_NODE_ID));
				BE2_HOST = host;
				BE2_PORT = port;
			}
			else {
				throw new IllegalArgumentException("Attempting to connect more than 2 BE nodes");
			}
			// try {
			// 	TNonblockingTransport transport = new TNonblockingSocket(host,port);                          
			// 	BcryptService.AsyncClient client = new BcryptService.AsyncClient(protocolFactory, clientManager, transport);                       
			// 	// backends.add(client);
			// 	// loads.add(0.0);


			// } catch (Exception e) {
			// 	throw new IllegalArgument(e.getMessage());
			// }
    }
    
    public List<String> delegatePasswordHash(List<String>password, short logRounds) throws IllegalArgument, org.apache.thrift.TException{
		System.out.println("hashing "+password.size()+" passwords");
		try {
			return computeHash(password,logRounds);
		} catch (Exception e){
			System.out.println(e.getMessage());
			throw new IllegalArgument(e.getMessage());
		}
    }
    public List<Boolean> delegatePasswordCheck(List<String> password, List<String> hash)throws IllegalArgument, org.apache.thrift.TException{
		System.out.println("checking "+password.size()+" passwords");
		try {
			return computeCheck(password, hash);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			throw new IllegalArgument(e.getMessage());
		}

	}

	class WorkerNode {
		private int id;
		private int load;

		WorkerNode(int id) {
			this.id = id;
			this.load = 0;
		}

		public int getLoad() {
			return this.load;
		}
		public void setLoad(int load) {
			this.load = load;
		}
		
		public String printNodeName() {
			if (this.id == 0) return "FE";
			if (this.id == 1) return "BE1";
			if (this.id == 2) return "BE2";
			return "BE3+";
		}
	}
}


