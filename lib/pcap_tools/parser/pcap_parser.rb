module PcapTools

  module Parser

    def self.load_file(f)
      packets = []
      File.open(f, 'rb') do |io|
        content = PcapFile.read(io)
        magic_number = content.header.magic.to_i.to_s(16)
        if magic_number == 'a0d0d0a'
          raise 'File is in pcap-ng, please convert it to pcap using editcap -F libpcap XXXX.pcapng XXXX.pcap'
        elsif magic_number != 'a1b2c3d4'
          raise "Wrong magic number [#{magic_number}], should be [a1b2c3d4]"
        end
        content.packets.each do |original_packet|
          packet = case content.header.linktype
                     when 113 then
                       LinuxCookedCapture.read(original_packet.data)
                     when 1 then
                       Ethernet.read(original_packet.data)
                     else
                       raise "Unknown network #{content.header.linktype}"
                   end
          packet.parent = original_packet
          while packet.respond_to?(:payload) && packet.payload.is_a?(BinData::Choice)
            packet = packet.payload
          end
          packets << packet
        end
      end
      packets
    end

  end

end
