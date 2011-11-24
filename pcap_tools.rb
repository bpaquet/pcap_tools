require 'rubygems'
require 'pcap'
require 'nokogiri'
require 'net/http'
require 'zlib'

module Net
  
  class HTTPRequest
    attr_accessor :time
  end

  class HTTPResponse
    attr_accessor :time
    
    def body= body
      @body = body
      @read = true
    end
    
  end
  
end

module PcapTools

  include Pcap
  
  class TcpStream < Array

    def insert_tcp sym, packet
      data = packet.tcp_data
      return unless data
      self << {:type => sym, :data => data, :time => packet.time, :from => packet.src, :to => packet.dst}
    end
    
    def rebuild_packets
      out = TcpStream.new
      current = nil
      self.each do |packet|
        if current
          if packet[:type] == current[:type]
            current[:data] += packet[:data]
          else
            out << current
            current = packet.clone
          end
        else
          current = packet.clone
        end
      end
      out << current if current
      out
    end

  end
  
  def load_mutliple_files dir
    Dir.glob(dir).sort{|a, b| File.new(a).mtime <=> File.new(b).mtime}.map{|file| Pcap::Capture.open_offline(file)}
  end
  
  module_function :load_mutliple_files
  
  def extract_http_calls_from_captures captures
    calls = []
    extract_tcp_streams(captures).each do |tcp|
      calls.concat(extract_http_calls(tcp))
    end
    calls
  end
  
  module_function :extract_http_calls_from_captures
  
  def extract_tcp_streams captures
    packets = []
    captures.each do |capture|
      capture.each do |packet|
        packets << packet
      end
    end
    
    streams = []
    (1..packets.size).each do |k|
      packet = packets[k]
      if packet.is_a?(TCPPacket) && packet.tcp_syn? && !packet.tcp_ack?
        flow_in = ""
        flow_out = ""
        kk = k
        tcp = TcpStream.new
        while kk < packets.size
          packet2 = packets[kk]
          if packet2.is_a?(TCPPacket)
            if packet.dport == packet2.dport && packet.sport == packet2.sport
              tcp.insert_tcp :out, packet2
              break if packet.tcp_fin? || packet2.tcp_fin?
            end
            if packet.dport == packet2.sport && packet.sport == packet2.dport
              tcp.insert_tcp :in, packet2
              break if packet.tcp_fin? || packet2.tcp_fin?
            end
          end
          kk += 1
        end
        streams << tcp
      end
    end
    streams
  end
  
  module_function :extract_tcp_streams
  
  def extract_http_calls stream
    rebuilded = stream.rebuild_packets
    calls = []
    data_out = ""
    data_in = nil
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
  
  module_function :extract_http_calls

  module HttpParser
    
    def parse_request stream
      headers, body = split_headers(stream[:data])
      line0 = headers.shift
      m = /(\S+)\s+(\S+)\s+(\S+)/.match(line0) or raise "Unable to parse first line of http request #{line0}"
      clazz = {'POST' => Net::HTTP::Post, 'GET' => Net::HTTP::Get, 'PUT' => Net::HTTP::Put}[m[1]] or raise "Unkown http request type #{m[1]}"
      req = clazz.new m[2]
      req['Pcap-Src'] = stream[:from]
      req['Pcap-Dst'] = stream[:to]
      req.time = stream[:time]
      req.body = body
      add_headers req, headers
      req.body.size == req['Content-Length'].to_i or raise "Wrong content-length for http request, header say #{req['Content-Length'].chomp}, found #{req.body.size}"
      req
    end

    module_function :parse_request
    
    def parse_response stream
      headers, body = split_headers(stream[:data])
      line0 = headers.shift
      m = /(\S+)\s+(\S+)\s+(\S+)/.match(line0) or raise "Unable to parse first line of http response #{line0}"
      resp = Net::HTTPResponse.send(:response_class, m[2]).new(m[1], m[2], m[3])
      resp.time = stream[:time]
      add_headers resp, headers
      if resp.chunked?
        resp.body = read_chunked("\r\n" + body)
      else
        resp.body = body
        resp.body.size == resp['Content-Length'].to_i or raise "Wrong content-length for http response, header say #{resp['Content-Length'].chomp}, found #{resp.body.size}"
      end
      resp.body = Zlib::GzipReader.new(StringIO.new(resp.body)).read if resp['Content-Encoding'] == 'gzip'
      resp
    end
    
    module_function :parse_response
    
    private
    
    def self.add_headers o, headers
      headers.each do |line|
        m = /\A([^:]+):\s*/.match(line) or raise "Unable to parse line #{line}"
        o.add_field m[1], m.post_match
      end 
    end
    
    def self.split_headers str
      index = str.index("\r\n\r\n")
      return str[0 .. index].split("\r\n"), str[index + 4 .. -1]
    end
    
    def self.read_chunked str
      return "" if str == "\r\n"
      m = /\r\n([0-9a-fA-F]+)\r\n/.match(str) or raise "Unable to read chunked body in #{str.split("\r\n")[0]}"
      len = m[1].hex
      return "" if len == 0
      m.post_match[0..len - 1] + read_chunked(m.post_match[len .. -1])
    end
    
  end
  
end
