module PcapTools

  class TcpStream < Array

    def insert_tcp(sym, packet)
      data = packet.payload
      return if data.size == 0
      self << {
        :type => sym,
        :size => data.size,
        :data => data,
        :from => packet.find_parent(PcapTools::Parser::IpPacket).src_addr,
        :to => packet.find_parent(PcapTools::Parser::IpPacket).dst_addr,
        :from_port => packet.src_port,
        :to_port => packet.dst_port,
        :time => packet.find_parent(PcapTools::Parser::PcapPacket).to_time
      }
    end

    def rebuild_streams
      out = TcpStream.new
      current = nil
      self.each do |packet|
        if current
          if packet[:type] == current[:type]
            current[:times] << {:offset => current[:size], :time => packet[:time]}
            current[:data] += packet[:data]
            current[:size] += packet[:size]
          else
            out << current
            current = packet.clone
            current[:times] = [{:offset => 0, :time => packet[:time]}]
          end
        else
          current = packet.clone
          current[:times] = [{:offset => 0, :time => packet[:time]}]
        end
      end
      out << current if current
      out
    end

  end
end