package edu.wisc.cs.sdn.simpledns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;

public class SimpleDNS 
{
	private final static int DNSPORT = 8053;
	private final static int MAXPACKETSIZE = 65535;

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
		DatagramSocket server; 
		DatagramPacket p;

		try {
			System.out.println("We are trying to connect...");
			server = new DatagramSocket(DNSPORT);
			System.out.println("server established....");
			server.receive(new DatagramPacket(packet, MAXPACKETSIZE));
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
				//handle query
				handleQuery(dnsPacket);
			}
			
			//server.close();
		} catch (IOException e) {
			System.out.println("ERROR: IO Exception");
			System.exit(1);
		}	
		return;
	}
	
	private static void handleQuery(DNS dnsPacket){
		
	}
}