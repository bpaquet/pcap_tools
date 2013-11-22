require 'bindata'

module PcapTools

  module Parser

    module HasParent

      attr_accessor :parent

    end

    class PcapFile < BinData::Record
      endian :little

      struct :header do
        uint32 :magic
        uint16 :major
        uint16 :minor
        int32 :this_zone
        uint32 :sig_figs
        uint32 :snaplen
        uint32 :linktype
      end

      array :packets, :read_until => :eof do
        uint32 :ts_sec
        uint32 :ts_usec
        uint32 :incl_len
        uint32 :orig_len
        string :data, :length => :incl_len
      end

    end

    # Present IP addresses in a human readable way
    class IPAddr < BinData::Primitive
      array :octets, :type => :uint8, :initial_length => 4

      def set(val)
        ints = val.split(/\./).collect { |int| int.to_i }
        self.octets = ints
      end

      def get
        self.octets.collect { |octet| "%d" % octet }.join(".")
      end
    end

    # TCP Protocol Data Unit
    class TCP_PDU < BinData::Record
      mandatory_parameter :packet_length

      endian :big

      uint16 :src_port
      uint16 :dst_port
      uint32 :seq
      uint32 :ack_seq
      bit4 :doff
      bit4 :res1
      bit2 :res2
      bit1 :urg
      bit1 :ack
      bit1 :psh
      bit1 :rst
      bit1 :syn
      bit1 :fin
      uint16 :window
      uint16 :checksum
      uint16 :urg_ptr
      string :options, :read_length => :options_length_in_bytes
      string :payload, :read_length => lambda { packet_length - payload.rel_offset }

      def options_length_in_bytes
        (doff - 5 ) * 4
      end

      def type
        "TCP"
      end

      include HasParent

    end

    # UDP Protocol Data Unit
    class UDP_PDU < BinData::Record
      mandatory_parameter :packet_length

      endian :big

      uint16 :src_port
      uint16 :dst_port
      uint16 :len
      uint16 :checksum
      string :payload, :read_length => lambda { packet_length - payload.rel_offset }

      def type
        "UDP"
      end

      include HasParent
    end

    # IP Protocol Data Unit
    class IP_PDU < BinData::Record
      endian :big

      bit4 :version, :asserted_value => 4
      bit4 :header_length
      uint8 :tos
      uint16 :total_length
      uint16 :ident
      bit3 :flags
      bit13 :frag_offset
      uint8 :ttl
      uint8 :protocol
      uint16 :checksum
      ip_addr :src_addr
      ip_addr :dst_addr
      string :options, :read_length => :options_length_in_bytes
      choice :payload, :selection => :protocol do
        tcp_pdu 6, :packet_length => :payload_length_in_bytes
        udp_pdu 17, :packet_length => :payload_length_in_bytes
        string :default, :read_length => :payload_length_in_bytes
      end

      def header_length_in_bytes
        header_length * 4
      end

      def options_length_in_bytes
        header_length_in_bytes - options.rel_offset
      end

      def payload_length_in_bytes
        total_length - header_length_in_bytes
      end

      def type
        "IP"
      end

      include HasParent
    end

    class MacAddr < BinData::Primitive
      array :octets, :type => :uint8, :initial_length => 6

      def set(val)
        ints = val.split(/\./).collect { |int| int.to_i }
        self.octets = ints
      end

      def get
        self.octets.collect { |octet| "%02x" % octet }.join(":")
      end
    end

    IPV4 = 0x0800
    class Ethernet < BinData::Record
      endian :big

      mac_addr :dst
      mac_addr :src
      uint16 :protocol
      choice :payload, :selection => :protocol do
        ip_pdu IPV4
        rest :default
      end

      include HasParent
    end

    class LinuxCookedCapture < BinData::Record
      endian :big

      uint16 :type
      uint16 :address_type
      uint16 :address_len
      array :octets, :type => :uint8, :initial_length => 8
      uint16 :protocol
      choice  :payload, :selection => :protocol do
        ip_pdu IPV4
        rest :default
      end

      include HasParent
    end

    def load_file f
      packets = []
      File.open(f, 'rb') do |io|
        content = PcapFile.read(io)
        raise 'Wrong endianess' unless content.header.magic.to_i.to_s(16) == "a1b2c3d4"
        content.packets.each do |original_packet|
          packet = case content.header.linktype
          when 113 then LinuxCookedCapture.read(original_packet.data)
          when 1 then Ethernet.read(original_packet.data)
          else raise "Unknown network #{content.header.linktype}"
          end
          packet.parent = original_packet
          while packet.respond_to?(:payload) && packet.payload.is_a?(BinData::Choice)
            packet.payload.parent = packet
            packet = packet.payload
          end
          packets << packet
        end
      end
      packets
    end

    module_function :load_file

  end

end