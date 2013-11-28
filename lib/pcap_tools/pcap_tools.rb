module PcapTools

  def self.extract_http_calls_from_captures(captures)
    calls = []
    extract_tcp_streams(captures).each do |tcp|
      calls.concat(extract_http_calls(tcp))
    end
    calls
  end

  def self.extract_tcp_streams(captures)
    packets = []
    captures.each do |capture|
      capture.each do |packet|
        packets << packet
      end
    end

    streams = []
    packets.each_with_index do |packet, k|
      if packet.current_class == PcapTools::Parser::TcpPacket && packet.syn == 1 && packet.ack == 0
        kk = k
        tcp = TcpStream.new
        while kk < packets.size
          packet2 = packets[kk]
          if packet.current_class == PcapTools::Parser::TcpPacket
            if packet.dst_port == packet2.dst_port && packet.src_port == packet2.src_port
              tcp.insert_tcp :out, packet2
              break if packet2.fin == 1 || packet2.rst == 1
            end
            if packet.dst_port == packet2.src_port && packet.src_port == packet2.dst_port
              tcp.insert_tcp :in, packet2
              break if packet2.fin == 1 || packet2.rst == 1
            end
          end
          kk += 1
        end
        streams << tcp
      end
    end
    streams
  end

  def self.extract_tcp_calls(stream)
    rebuilded = stream.rebuild_streams
    calls = []
    k = 0
    while k < rebuilded.size
      begin
        req = HttpParser::parse_request(rebuilded[k])
        resp = k + 1 < rebuilded.size ? HttpParser::parse_response(rebuilded[k + 1]) : nil
        calls << [req, resp]
      rescue Exception => e
        warn "Unable to parse http call : #{e}"
      end
      k += 2
    end
    calls
  end

end
