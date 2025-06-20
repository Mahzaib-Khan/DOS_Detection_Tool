



#----------importing modules and classes which are required in code----------# 

import socket,pcapy,sys,datetime
from struct import *		

#----------Declaration of global variable to be used by all the classes and methods.----------#

store_ip_seq_dict={}		#global dictionary to ip and seq+1 for packet with syn flag
store_seq_no=[]			#global list to store seq+1 for packet with syn flag
s_failedTCP=[]			#global list to store sender ip address , who fails to complete tcp 3 way handshake
d_failedTCP=[]			#global list to store destination ip address , who fails to complete tcp 3 way handshake
choice=""			#global variable to store user choice of devices to sniff on.
cpack=""			#global variable to store packet
Loopflag=True			#global boolean variable
pcapFile=""			#variable to store device name to sniff on.
failedSeq=[]			#global list to store failed seq number.
store_dest_IP={}		#global dictionary to store failed tcp handshake destination ip
s_Failed_RST={}			#global dictionary to store sender ip address with failed rst connection
d_Failed_RST={}			#global dictionary to store destination ip address with failed rst connection
store_Seq_RST=[]		#global list to store seq of failed rst
store_ack_RST=[]		#global list to store ack of failed rst
s_IP_failedRST=[]		#global list to store sender ip address ,which has failed rst connection 
d_IP_failedRST=[]		#global list to store destination ip address ,which has failed rst connection
store_Seq_RST_ACK=[]
store_ack_RST_ACK=[]
s_IP_RST_ACK=[]
d_IP_RST_ACK=[]

#----------Main class of this program ,whose constructor call sniffpacket method of selectNic class.----------#

class PcapySnifferTool:		#Main class of this program ,whose constructor call sniffpacket method of selectNic class.
    def __init__(self):		#constructor of class.
        s=selectNic()		#object created for selectNic class.
        s.sniffPacket()		#calling sniffPacket method of selectNic class.

#----------Class to get user choice for packet sniffing either from file or NIC card----------#   
     
class selectNic:
    selectedNic=''
    def __init__(self):#constructor of selectNic class
        global choice
        choice=raw_input("Type 'F' to sniff from 'Pcap Packet File' or 'I' to Sniff from Network Interface :")#get user input F/I
        choice=choice.upper()
        while(choice!='I' and choice!='F'):#validation check , if not F/I again ask user input
            print "\nError Code UI100: Please enter Valid Input \n"
            choice=raw_input("Type 'F' to sniff from 'Pcap Packet File' or 'I' to Sniff from Network Interface :")
            choice=choice.upper()
        if choice=='F':
            self.pcapFileImport()#if F call pcapFileImport method
        elif choice=='I':
            self.pcapNicCapture()#if I call pcapNicCapture

#----------Method to find all active NIC's and take user input to sniff on particular NIC----------#        
                         
    def pcapNicCapture(self):
        interface=pcapy.findalldevs() #find all active Interfaces
        print "Interfaces available :"
        for nic in interface:#loop to display acitve interfaces
            print nic
        selectNic.selectedNic=raw_input("Enter interface name to sniff :")#user input for interfaces
        try:
            pcapy.open_live(selectNic.selectedNic,65536,1,0)
        except:
            print "Error Code I300 :Wrong Interface Name , please Enter valid Interface Name."
            self.pcapNicCapture()
       
        
#----------Method to take user input , for file which is in pcap format----------#        
        
    def pcapFileImport(self):
        global pcapFile
        pcapFile=raw_input("Enter Absolute File Path :")#user input for file name
        try:
            pcapy.open_offline(pcapFile)
        except:
            print "Error Code F200 :Wrong File Name , please Enter valid File Name."
            self.pcapFileImport()
            
        
        
#----------Main method which will sniff packet and call  methods from decodePacket class to parse the packets.It will also identify failed TCP and RST connection and IP addresses----------#       
            
    def sniffPacket(self):
        global Loopflag
        global cpack
        global choice
        
        if choice=='I':
            Loopflag=True
            cpack=pcapy.open_live(selectNic.selectedNic,65536,1,0)#capture packets on selected interfaces and store it to cpack variable
            print "\nSniffing started on : "+ selectNic.selectedNic+'\n'
            
                    
        elif choice=='F':
            global pcapFile
            print "\nSniffing started on File: %s"%(pcapFile)+'\n'
            cpack=pcapy.open_offline(pcapFile)#store file information in cpack variable
            
                
            
    
        try:
            
            while(Loopflag):#while loop to parse one packet at a time
                (header,packet)=cpack.next()#store packet in a packet variable
                d=decodePacket()#creating object of decodePacket class
                d.decode_ethernet(packet)#call decode_ethernet method of decodePacket class and decode 14 byte of packets.
                if d.ethernet_protocol=="8":#if ethernet_protocol has value 8 then call decode_IPv4 method to parse 14-34 byte of packet
                    d.decode_IPv4(packet)
                if d.ip4_protocol=="6":#if ipv4_protocol has value 6 then call decode_TCP method to parse 34-54 byte of packet
                    print 'Timestamp: '+str(datetime.datetime.now())+'\n'
                    print "Source MAC :%s Destination MAC :%s \nSource IP Addr :%s Destination IP Addr :%s \nIP Version :%d \nIP Header Len :%d \nTTL :%d "%(d.source_Mac,d.dest_Mac,d.sender_ip,d.receiver_ip,d.ip4_vers,d.ip4_ihl,d.ip4_ttl)
                    d.decode_TCP(packet,d.ip4_length)
                    if d.flags==2:#if packet has SYN flag or value of d.flag==2 then store its seq+1 and sender ip address in dictionary and also store seq+1 in list.
                        global store_dest_IP#variable to store destination IP
                        global store_seq_no  #list to store seq+1 number for syn packet
                        global store_ip_seq_dict #dictionary to store ip and seq+1 numuber for syn packet
                        global s_Failed_RST #variable to store sender ip with RST flag
                        global d_Failed_RST #variable to store destination IP with RST flag
                        global store_Seq_RST #varaible to store seq+1 for RST flag
                        global store_ack_RST #variable to stoer ack number for RST flag
                        global store_Seq_RST_ACK
                        global failedSeq
                        seq_no=d.seq+1          #variable to store seq+1
                        s_ip=(d.sender_ip)      #variable to store sender ip address
                        d_ip=(d.receiver_ip)
                        store_ip={seq_no:s_ip}  #dictionary to store seq+1 and ip
                        store_d_ip={seq_no:d_ip}
                        store_seq_no.append(seq_no) #appending seq_no list to store_seq_no
                        store_ip_seq_dict.update(store_ip) #updating dict with store_ip dict
                        store_dest_IP.update(store_d_ip)
                        s_Failed_RST=store_ip_seq_dict
                        d_Failed_RST=s_Failed_RST
                        store_Seq_RST=store_seq_no
                        store_Seq_RST_ACK=store_seq_no
                        
                    elif d.flags==16:                       #check if package has ACK flag
                        for seq in store_seq_no:            #storing store_seq_no value in seq via while loop
                            if d.seq==seq:                  #check if ACK packet seq no is equal to SYN packet seq+1
                                store_seq_no.remove(seq)    # if yes then remove seq+1 from store_seq_no
                    elif d.flags==4:
                        for rst in store_Seq_RST:
                            if d.ack==rst:
                                 store_ack_RST.append(d.ack)
                    elif d.flags==20:
                        for rst_ack in store_Seq_RST_ACK:
                            if d.ack==rst_ack:
                                store_ack_RST_ACK.append(d.ack)
        except KeyboardInterrupt:
            print "Sniffing Interrupted"
        except Exception :
            print "File Finished"
                        
                        
                        
        finally :       #exception to handle keyboard interruption and display fialed TCP and RST connections.
            print "\nPacket sniffing Interrupted.\n"
            global failedSeq
            global s_failedTCP
            global d_failedTCP
            global s_IP_failedRST
            global d_IP_failedRST
            global s_IP_failedRST
            global d_IP_failedRST
            global s_IP_RST_ACK
            global d_IP_RST_ACK
            for secq in store_seq_no:
                
                s=store_ip_seq_dict[secq]
                s_failedTCP.append(s)
                dd=store_dest_IP[secq]
                d_failedTCP.append(dd)
                synSeq=secq-1
                failedSeq.append(synSeq)
            len_failedTCP=len(s_failedTCP)
            print '\n'
            print "Total No of failed TCP 3 way handshake Connection :"+str(len(s_failedTCP))+'\n'
            i=0
            while ( len_failedTCP!=0 ):
                print 'Sender IP :'+str(s_failedTCP[i])+' SEQ No :'+str(failedSeq[i])+' Destination IP :'+str(d_failedTCP[i])
                i=i+1
                len_failedTCP=len_failedTCP-1

            rst_seq_no=[]
            rst_ack_no=[]
            ack_rst_syn_seq_no=[]
            ack_rst_ack_ack_no=[]
            j=0
            k=0

            for rstACK in store_ack_RST:
                s_RST=s_Failed_RST[rstACK]
                s_IP_failedRST.append(s_RST)
                d_RST=d_Failed_RST[rstACK]
                d_IP_failedRST.append(d_RST)
                rst_seq_no.append(rstACK-1)
                rst_ack_no.append(rstACK)

            for rstACK in store_ack_RST_ACK:
                
                s_RST_ACK=s_Failed_RST[rstACK]
                s_IP_RST_ACK.append(s_RST_ACK)
                d_RST_ACK=d_Failed_RST[rstACK]
                d_IP_RST_ACK.append(d_RST_ACK)
                ack_rst_syn_seq_no.append(rstACK-1)
                ack_rst_ack_ack_no.append(rstACK)
                

            print '\nTotal no of Failed TCP connection with RST :'+str(len(s_IP_failedRST)+len(s_IP_RST_ACK))+'\n'
        
            
            len_s_IP_failedRST=len(s_IP_failedRST)
            while(len_s_IP_failedRST!=0):
                print 'Sender IP :'+str(s_IP_failedRST[j])+' Seq No :'+str(rst_seq_no[j])+'Flag : SYN '+'RST Sender IP :'+str(d_IP_failedRST[j])+' Ack No :'+str(rst_ack_no[j])+' Flag:RST'
                j=j+1
                len_s_IP_failedRST=len_s_IP_failedRST-1
            len_s_IP_RST_ACK=len(s_IP_RST_ACK)
            
            while(len_s_IP_RST_ACK!=0):
                print 'Sender IP :%s Seq NO :%s Destination IP :%s Ack No :%s'%(str(s_IP_RST_ACK[k]),str(ack_rst_syn_seq_no[k]),str(d_IP_RST_ACK[k]),str(ack_rst_ack_ack_no[k]))
                k=k+1
                len_s_IP_RST_ACK=len_s_IP_RST_ACK-1
                
        
                
                
        

#----------Class which has method to parse ethernet,ipv4 and TCP packets.----------#                
                      
                                                              
class decodePacket :
    dest_Mac=""                 #class varible to store destination MAC address
    source_Mac=""               #class varible to store sender MAC address
    ethernet_protocol=""        #class varible to store type of ethner header , it defines the next protocol in the packet
    ip4_vers=0                  #class varible to store ip header version, which is 4
    ip4_ihl=0                   #class varible to store ip header length
    ip4_ttl=0                   #class varible to store time to live value
    ip4_length=0                #class varible to store total length of ip packet
    ip4_protocol=""             #class varible to store next protocol in packet which comes after ip protocol
    sender_ip=""                #class varible to store sender ip address
    receiver_ip=""              #class varible to store destination ip address
    flagType=""                 #calss to store flag type value, it can be syn ,ack, syn/ack,rst,psh/ack,fin/ack
    seq=0                       #class varible to store sequence number
    ack=0                       #class varible to store acknowledge number
    flags=0                     #calss varibale to store flag value it can be 2,4,8,16,34,27
    
#----------Method to parse ethernet header and data----------#    
    
    def decode_ethernet(self,packet):
        length=14
        header=packet[:length]
        ethernet=unpack("!6p6pH",header)
        dest_Mac="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(packet[0]) , ord(packet[1]) , ord(packet[2]), ord(packet[3]), ord(packet[4]) , ord(packet[5]))
        self.dest_Mac=str(dest_Mac)
        source_Mac="%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(packet[6]) , ord(packet[7]) , ord(packet[8]), ord(packet[9]), ord(packet[10]) , ord(packet[11]))
        self.source_Mac=str(source_Mac)
        ethernet_protocol=str(socket.ntohs(ethernet[2]))
        self.ethernet_protocol=ethernet_protocol
        
#----------Method to parse IPv4 header and data----------#        

    def decode_IPv4(self,packet):
        
        IPv4_header=packet[14:34]
        ip4=unpack('!BBHHHBBH4s4s' ,IPv4_header)
        vers_ihl = ip4[0]
        ip4_vers=vers_ihl >> 4
        self.ip4_vers=ip4_vers
        ip4_ihl=vers_ihl & 15
        self.ip4_ihl=int(ip4_ihl)
        ip4_tos=ip4[1]
        ip4_length=ip4_ihl*4
        self.ip4_length=ip4_length
        ip4_ttl=ip4[5]
        self.ip4_ttl=ip4_ttl
        ip4_protocol=str(ip4[6])
        self.ip4_protocol=ip4_protocol
        sender_ip=socket.inet_ntoa(ip4[8])
        self.sender_ip=str(sender_ip)
        receiver_ip=socket.inet_ntoa(ip4[9])
        self.receiver_ip=str(receiver_ip)
        
        
#----------Method to parse TCP header and data-----------#
        
    def decode_TCP(self,packet,ip4_length):
        
        protocol="TCP"
        eth_ip_length=14+ip4_length
        tcp_header=packet[eth_ip_length:eth_ip_length+20]
        tcp=unpack('!HHLLBBHHH' , tcp_header)
        s_port=tcp[0]
        d_port=tcp[1]
        seq=tcp[2]
        decodePacket.seq=seq
        ack=tcp[3]
        decodePacket.ack=ack
        tpch_len_reserved = tcp[4]
        tcph_len=tpch_len_reserved >> 4
        flags=tcp[5]
        decodePacket.flags=flags
        flags_dict={1:'FIN',2:'SYN',4:'RST',8:'PSH',16:'ACK',32:'URG',64:'ECE',128:'CWR',18:'SYN/ACK',24:'PSH,ACK',17:'FIN/ACK',20:'RST/ACK'};
        for flag in flags_dict:
            if flag==flags:
                fgType=flags_dict[flags]
                decodePacket.flagType=fgType
        print 'Protocol:'+protocol+'\nSource_Port: '+ str(s_port)+'\nReceiver_Port: '+str(d_port)+'\nSeq: '+str(seq) +'\nAck: '+str(ack) +'\nTCP_Header_Lenght: '+str(tcph_len)+'\nTCP_Flags_Value: '+str(flags)+ '\nFlag_Type: '+decodePacket().flagType
        total_header_size=14+ip4_length+tcph_len * 4
        total_data_size=len(packet)-total_header_size
        data=packet[total_header_size:]
        print 'Total_Data_size :%d'%(total_data_size)+'\n'
        print 'Data :'+data
        print '\n'
        print '***************************************************************************************************************************************************\n'

    
#----------Defalut line in python program ,it is the first line which get executed . constructor of PcapySnifferTool class is getting called here----------#

if __name__ == "__main__":
    PcapySnifferTool()


