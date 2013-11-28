module PcapTools

  module HttpParser

    def self.parse_request(stream)
      headers, body = split_headers(stream[:data])
      line0 = headers.shift
      m = /(\S+)\s+(\S+)\s+(\S+)/.match(line0) or raise "Unable to parse first line of http request #{line0}"
      clazz = {
        'POST' => Net::HTTP::Post,
        'HEAD' => Net::HTTP::Head,
        'GET' => Net::HTTP::Get,
        'PUT' => Net::HTTP::Put
      }[m[1]] or raise "Unknown http request type [#{m[1]}]"
      req = clazz.new m[2]
      req['Pcap-Src'] = stream[:from]
      req['Pcap-Src-Port'] = stream[:from_port]
      req['Pcap-Dst'] = stream[:to]
      req['Pcap-Dst-Port'] = stream[:to_port]
      req.time = stream[:time]
      req.body = body
      req['user-agent'] = nil
      req['accept'] = nil
      add_headers req, headers
      if req['Content-Length']
        req.body.size == req['Content-Length'].to_i or raise "Wrong content-length for http request, header say [#{req['Content-Length'].chomp}], found #{req.body.size}"
      end
      req
    end

    def self.parse_response(stream)
      headers, body = split_headers(stream[:data])
      line0 = headers.shift
      m = /^(\S+)\s+(\S+)\s+(.*)$/.match(line0) or raise "Unable to parse first line of http response [#{line0}]"
      resp = Net::HTTPResponse.send(:response_class, m[2]).new(m[1], m[2], m[3])
      resp.time = stream[:time]
      add_headers resp, headers
      if resp.chunked?
        resp.body = read_chunked("\r\n" + body)
      else
        resp.body = body
        if resp['Content-Length']
          resp.body.size == resp['Content-Length'].to_i or raise "Wrong content-length for http response, header say [#{resp['Content-Length'].chomp}], found #{resp.body.size}"
        end
      end
      begin
        resp.body = Zlib::GzipReader.new(StringIO.new(resp.body)).read if resp['Content-Encoding'] == 'gzip'
      rescue Zlib::GzipFile::Error, Zlib::GzipFile::DataError
        warn "Response body is not in gzip: [#{resp.body}]"
      end
      resp
    end

    private

    def self.add_headers(o, headers)
      headers.each do |line|
        m = /\A([^:]+):\s*/.match(line) or raise "Unable to parse header line [#{line}]"
        o[m[1]] = m.post_match
      end
    end

    def self.split_headers(str)
      index = str.index("\r\n\r\n")
      return str[0 .. index].split("\r\n"), str[index + 4 .. -1]
    end

    def self.read_chunked(str)
      if str.nil? || (str == "\r\n")
        return ''
      end
      m = /\r\n([0-9a-fA-F]+)\r\n/.match(str) or raise "Unable to read chunked body in #{str.split("\r\n")[0]}"
      len = m[1].hex
      return '' if len == 0
      m.post_match[0..len - 1] + read_chunked(m.post_match[len .. -1])
    end

  end

end