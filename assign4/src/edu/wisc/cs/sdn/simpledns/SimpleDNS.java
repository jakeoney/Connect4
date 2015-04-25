package edu.wisc.cs.sdn.simpledns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.List;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class SimpleDNS 
{
	private final static int DNSPORT = 53;
	private final static int LOCALDNSPORT = 8053;
	private final static int MAXPACKETSIZE = 65535;

	static DatagramSocket server; 

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
				runDNS(rootServer, ec2Path);
		}
		else
		{
			System.out.println("Error: missing or additional arguments");
			System.exit(1);
		}
		System.exit(0);
	}
	
	private static void runDNS(String rootServerIP, String ec2Path){
		
		byte packet[] = new byte[MAXPACKETSIZE];
		DNS dnsPacket;
		DNSQuestion question;
		DatagramPacket p;

		try {
			System.out.println("We are trying to connect...");
			server = new DatagramSocket(LOCALDNSPORT);
			System.out.println("server established....");
			
	        DatagramPacket dPkt = new DatagramPacket(packet, packet.length);
			server.receive(dPkt);
			System.out.println("got information");
			
			dnsPacket = DNS.deserialize(packet, packet.length);
			
			//We don't need to process it if it's not a std query
			if(dnsPacket.getOpcode() != DNS.OPCODE_STANDARD_QUERY)
			{
				server.close();
				return;
			}
			System.out.println("We have a standard Query!");
			//assume each packet has only 1 question
			question = dnsPacket.getQuestions().get(0);
			if(question.getType() == DNS.TYPE_A || question.getType() == DNS.TYPE_AAAA || question.getType() == DNS.TYPE_CNAME || question.getType() == DNS.TYPE_NS){
				System.out.println("We have a good question!");
				printInfo(dnsPacket);
				//handle query
				handleQuery(dnsPacket, rootServerIP, dPkt);
			}
			
			//server.close();
		} catch (IOException e) {
			System.out.println("ERROR: IO Exception");
			System.exit(1);
		}	
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
			//System.out.println("constructed query");
			query = new DatagramPacket(dnsPkt.serialize(), 0, dnsPkt.getLength(), address, DNSPORT);
			//System.out.println("Before Send "+dnsPkt.toString());

			//System.out.println("sending query");
			socket.send(query);
        
			//System.out.println("waiting to receive packet");

			socket.receive(new DatagramPacket(packet, packet.length));

			//System.out.println("received packet!!!!");

			dnsPkt = DNS.deserialize(packet, packet.length);    
			//printInfo(dnsPkt);
			//System.out.println("After Send "+dnsPkt.toString());
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
						//System.out.println(address.toString());
						break;
					}
				}
				
				SimpleDNS.addEntriesToHostPkt(dnsPkt, toSendToHost);

				List<DNSResourceRecord> answers = dnsPkt.getAnswers();
				//once we are finished... maybe
				if(answers.size() > 0){
					for(DNSResourceRecord ans : dnsPkt.getAnswers()){
						toSendToHost.addAnswer(ans);
					}
					//System.out.println("ever here?");
					printInfo(toSendToHost);
					sendToClient(toSendToHost, toReturnToSender);
					done = true;
				}
			}

			SimpleDNS.prepareNewQuery(dnsPkt);
			
			ttl--;	
		}
		server.close();
        socket.close();
        System.exit(0);
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
		DatagramPacket answer = new DatagramPacket(dnsPkt.serialize() , 0, dnsPkt.getLength(), toReturnToSender.getSocketAddress());
		System.out.println("sending answer");
		server.send(answer);
		System.out.println("answer sent");
	}
	
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