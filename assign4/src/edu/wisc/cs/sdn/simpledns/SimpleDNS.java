package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataName;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class SimpleDNS 
{
	private final static int DNSPORT = 53;
	private final static int LOCALDNSPORT = 8053;
	private final static int MAXPACKETSIZE = 65535;

	static DatagramSocket server; 
	static HashMap<String, String> ec2Map = new HashMap<String, String>();

	public static void main(String[] args)
	{
		int i = 0;
		String arg;
		boolean rootServerFound = false;
		boolean ec2PathFound = false;
		String rootServer = null;
		String ec2Path = null;

		System.out.println("Hello, DNS!"); 
		if(args.length == 4)
		{
			while(i < args.length) 
			{
				arg = args[i++];

				if(arg.equals("-r")){
					rootServerFound = true;
					try{
						rootServer = args[i++];
					} catch(NumberFormatException e)
					{
						System.out.println("");
						System.exit(1);
					}
				}
				else if(arg.equals("-e"))
				{
					ec2PathFound = true;
					ec2Path = args[i++];
				}
				else
				{
					System.out.println("Error: missing or additional arguments");
					System.exit(1);
				}
			}
		}
		else
		{
			System.out.println("Error: missing or additional arguments");
			System.exit(1);
		}

		if(ec2PathFound && rootServerFound)
		{
			loadEC2(ec2Path);
			runDNS(rootServer);
		}
		else
		{
			System.out.println("Error: missing or additional arguments");
			System.exit(1);
		}
		System.exit(0);
	}

	private static void runDNS(String rootServerIP){

		byte packet[] = new byte[MAXPACKETSIZE];
		DNS dnsPacket;
		DNSQuestion question;

		try {
			server = new DatagramSocket(LOCALDNSPORT);
			while(true){
				DatagramPacket dPkt = new DatagramPacket(packet, packet.length);
				server.receive(dPkt);
				dnsPacket = DNS.deserialize(packet, packet.length);

				//We don't need to process it if it's not a std query
				if(dnsPacket.getOpcode() == DNS.OPCODE_STANDARD_QUERY)
				{
					//assume each packet has only 1 question
					question = dnsPacket.getQuestions().get(0);
					if(question.getType() == DNS.TYPE_A || question.getType() == DNS.TYPE_AAAA || 
					   question.getType() == DNS.TYPE_CNAME || question.getType() == DNS.TYPE_NS)
					{
						//handle query
						handleQuery(dnsPacket, rootServerIP, dPkt);
					}
				}
			}
		} catch (IOException e) {
			System.out.println("ERROR: IO Exception");
			server.close();
			System.exit(1);
		}
		server.close();
		return;
	}


	private static void handleQuery(DNS dnsPkt, String ip, DatagramPacket toReturnToSender) throws IOException
	{
		byte packet[] = new byte[MAXPACKETSIZE];
		DatagramPacket query;
		InetAddress address = null;
		DatagramSocket socket = new DatagramSocket(DNSPORT);
		boolean done = false;
		address = InetAddress.getByName(ip);
		int ttl = 100; //incase host unknown
		DNS toSendToHost = dnsPkt;

		while(!done && (ttl > 0)){
			query = new DatagramPacket(dnsPkt.serialize(), 0, dnsPkt.getLength(), address, DNSPORT);
			socket.send(query);
			
			socket.receive(new DatagramPacket(packet, packet.length));
			dnsPkt = DNS.deserialize(packet, packet.length);    
			if(!dnsPkt.isRecursionDesired()){
				//forward back to host
				sendToClient(dnsPkt, toReturnToSender);
				done = true;
			}
			else{
				dnsPkt.setQuery(true);
				for(DNSResourceRecord adtl : dnsPkt.getAdditional()){
					if(adtl.getType() == DNS.TYPE_A || adtl.getType() == DNS.TYPE_AAAA){
						DNSRdataAddress addr = (DNSRdataAddress) adtl.getData();
						String a = addr.toString();
						address = InetAddress.getByName(a);
						break;
					}
				}

				SimpleDNS.addEntriesToHostPkt(dnsPkt, toSendToHost);

				List<DNSResourceRecord> answers = dnsPkt.getAnswers();
				if(answers.size() > 0){
					for(DNSResourceRecord ans : dnsPkt.getAnswers()){
						toSendToHost.addAnswer(ans);
					}
					sendToClient(toSendToHost, toReturnToSender);
					//printInfo(toSendToHost);
					done = true;
				}
			}

			SimpleDNS.prepareNewQuery(dnsPkt);

			ttl--;	
		}
		socket.close();
	}

	private static void addEntriesToHostPkt(DNS pkt, DNS toSend){
		int adtlSize = pkt.getAdditional().size();
		int authSize = pkt.getAuthorities().size();

		for(int i = 0; i < adtlSize - 1; i++){
			toSend.addAdditional(pkt.getAdditional().get(i));
		}
		for(int i = 0; i < authSize; i++){
			toSend.addAuthority(pkt.getAuthorities().get(i));
		}
	}

	private static void prepareNewQuery(DNS pkt){

		int adtlSize = pkt.getAdditional().size();
		int authSize = pkt.getAuthorities().size();
		pkt.setQuery(true);
		pkt.setRecursionAvailable(true);
		pkt.setRecursionAvailable(true);
		for(int i = 0; i < adtlSize - 1; i++){
			pkt.removeAdditional(pkt.getAdditional().get(0));
		}
		for(int i = 0; i < authSize; i++){
			pkt.removeAuthority(pkt.getAuthorities().get(0));
		}
	}

	private static void sendToClient(DNS dnsPkt, DatagramPacket toReturnToSender) throws IOException{
		//if it is type IPv4, check to see if it is associated with Amazons EC2
		if(dnsPkt.getQuestions().get(0).getType() == DNS.TYPE_A){
			checkIfInEC2Region(dnsPkt);
		}
		DatagramPacket answer = new DatagramPacket(dnsPkt.serialize() , 0, dnsPkt.getLength(), toReturnToSender.getSocketAddress());
		server.send(answer);
		System.out.println("answer sent");
	}

	private static void checkIfInEC2Region(DNS dnsPkt){
		//make 24-32 bits = 0;
		/*
/22 255.255.252.0  0
/21 255.255.248.0  1
/20 255.255.240.0  2
/19 255.255.224.0  3
/18 255.255.192.0  4
/17 255.255.128.0  5
/16 255.255.0.0    6
/15 255.254.0.0    7
/14 255.252.0.0    8
/13 255.248.0.0    9
		 */
		if(dnsPkt.getAdditional().size() > 0){
			int val = 256;
			int slash = 24;
			DNSRdataAddress addr = (DNSRdataAddress) dnsPkt.getAnswers().get(0).getData();
			String originalIP = addr.getAddress().toString().substring(1);
			int lastDecimal = originalIP.lastIndexOf('.');
			originalIP = originalIP.substring(0, lastDecimal);

			String testSubnet = originalIP; 
			for(int i = 0; i < 12; i++){
				testSubnet = originalIP;
				int nextDecimal = originalIP.lastIndexOf('.');
				int item = Integer.parseInt(originalIP.substring(nextDecimal +1, originalIP.length()));
				int newSubnet =  (((int)(val - Math.pow(2, i%8))) & item);
				if(i < 8)
					testSubnet = testSubnet.substring(0, nextDecimal + 1) + newSubnet + ".0/" + slash;
				else
					testSubnet = testSubnet.substring(0, nextDecimal + 1) + newSubnet + ".0.0/" + slash;
				slash--;
				if(ec2Map.containsKey(testSubnet)){
					createEC2Record(dnsPkt, testSubnet, addr.getAddress());
					break;
				}
				//for doing the slash <= 16
				if(i == 7){
					originalIP = originalIP.substring(0, nextDecimal);
				}
			}
		}
	}

	private static void createEC2Record(DNS dnsPkt, String ec2Server, InetAddress ipOnServer){
		String location = ec2Map.get(ec2Server);
		DNSResourceRecord record;
		DNSRdataName name = new DNSRdataName(location + "-" + ipOnServer.toString().substring(1));
		record = new DNSResourceRecord(dnsPkt.getQuestions().get(0).getName(), /*DNS.TYPE_EC2*/(short)16, name);
		dnsPkt.addAnswer(record);
	}

	private static void loadEC2(String ec2Path){
		BufferedReader reader = null;
		String line = null;
		String cvsSplitBy = ",";
		try 
		{
			FileReader fileReader = new FileReader(ec2Path);
			reader = new BufferedReader(fileReader);
		}
		catch (FileNotFoundException e) 
		{
			System.err.println(e.toString());
			System.exit(2);
		}

		while (true)
		{
			// Read a route entry from the file
			try 
			{ line = reader.readLine(); }
			catch (IOException e) 
			{
				System.err.println(e.toString());
				try { reader.close(); } catch (IOException f) {};
				System.exit(3);
			}

			// Stop if we have reached the end of the file
			if (null == line)
			{ break; }

			String[] entry = line.split(cvsSplitBy);
			String ip = entry[0];
			String location = entry[1];
			ec2Map.put(ip, location);
		}

		// Close the file
		try { reader.close(); } catch (IOException f) {};
	}

	//used for debugging
	private static void printInfo(DNS pkt){
		System.out.println("Question");
		System.out.println(pkt.getQuestions().get(0).toString());
		System.out.println("Answers");

		for(DNSResourceRecord ans : pkt.getAnswers()){
			System.out.println(ans.toString());
		}
		System.out.println("Authority");
		for(DNSResourceRecord auth : pkt.getAuthorities()){
			System.out.println(auth.toString());
		}
		System.out.println("Additional");
		for(DNSResourceRecord addt : pkt.getAdditional()){
			System.out.println(addt.toString());
		}
	}
}