# What is it ?

PCapTools is a ruby library to process pcap file from [wireshark](http://www.wireshark.org/) or [tcpdump](http://www.tcpdump.org/).

PCapTools uses [tshark](http://www.wireshark.org/docs/man-pages/tshark.html) to process the pcap file, and run some analysis on it. Tshark is bundled with [wireshark](http://www.wireshark.org/download.html).

There are two ways to use PCapTools

* as a command line tools
* as a ruby library

## As a command line tools

Main functionnalities :

* Rebuild tcp streams
* Extract and parse http requests

### Install

Ensure `tshark` is installed. If not, check your wireshark install.

    tshark -v

Install pcap_tools

    gem install pcap_tools

### Command line options

    pcap_tools --help

    Usage: pcap_tools_http [options] pcap_files
        --no-body                    Do not display body
        --tshark_path                Path to tshark executable
        --one-tcp-stream [index]     Display only one tcp stream
        --mode [MODE]                Parsing mode : http, tcp, frame, tcp_count. Default http

### Typical use

    tcpdump -w out.pcap -s0 port 80
    pcap_tools out.pcap


## As a ruby library

### Install

Ensure `tshark` is installed. If not, check your wireshark install.

    tshark -v

Declare dependency to `pcap_tools` in your Gemfile.

    gem 'pcap_tools'

### How to use it

The best example is the [pcap_tools command line script](https://github.com/bpaquet/pcap_tools/blob/master/bin/pcap_tools).

Pcap_tools is an event processor : `tshark` returns an XML Flow, which is parsed with a SAX processor. Each packet is processed by a TCP processor, which build streams. Each streams is processed by an HTTP processor, which rebuild HTTP request / response.

#### Loading files

    PcapTools::Loader::load_file(f, {:tshark => OPTIONS[:tshark_path]}) do |index, packet|
    end

Each packet is a ruby object containing the main attributes found in the packet, extracted with tshark.

You have to use a packet processor to process this packet. The main one is `PcapTools::TcpProcessor`.

### Extract tcp streams

    processor = PcapTools::TcpProcessor.new
    PcapTools::Loader::load_file(f, {:tshark => OPTIONS[:tshark_path]}) do |index, packet|
      processor.inject index, packet
    end

The [TCPProcessor](https://github.com/bpaquet/pcap_tools/blob/master/lib/pcap_tools/packet_processors/tcp.rb) rebuild streams from IP raw packets. To use the streams, you have to add some streams processors into the TCP Processor. TCP Processor will run each processors in the given order, passing result between them. Streams format is described below.

    processor.add_stream_processor PcapTools::TcpStreamRebuilder.new

The [TcpStreamRebuilder](https://github.com/bpaquet/pcap_tools/blob/master/lib/pcap_tools/stream_processors/http.rb) reassembles contiguous packet, for example the packets containing a big HTTP Response.

    processor.add_stream_processor PcapTools::HttpExtractor.new

The [HttpExtractor](https://github.com/bpaquet/pcap_tools/blob/master/lib/pcap_tools/stream_processors/rebuilder.rb) build HTTP request and response from streams.

Please read the code to build your own stream processor. Do not be afraid, it's easy :)

Note : the TCPProcessor is not able to rebuild tcp stream which do not start in the pcap file. For example, if you launch tcpdump after a long running Oracle DB connection, TCPProcessor will not show the Oracle DB connection.

### Data format

Streams objects

A `tcp_streams` is an array of hash, each hash has some keys :

* `:type` : `:in` or `:out`, if the packet was sent or received
* `:time` : timestamp of the packet.
* `:data` : payload of packet.
* `:size` : payload size.

HTTP Objects

A `http_call` is an array of two objects :

* The http request, an instance of `Net::HTTPRequest`, eg `Net::HTTPGet` or `Net::HTTPPost`. You can use this object
like any http request of [std lib `net/http`](http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/index.html)
  * `req.path` : get the request path
  * `req['User-Agent']` : get the User-Agent
  * `req.body` : get the request body
  * ...
* The http response, an instance of `Net::HTTPResponse`, eg `Net::HTTPOk` or `Net::HTTPMovedPermanently`. You can use this object
  like any http response of [std lib `net/http`](http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/index.html)
  * `resp.code` : get the http return code
  * `resp['User-Agent']` : get the User-Agent
  * `resp.body` : get the request body
  * ...

The response can be `nil` if there is no response in the tcp stream.

The request and response object have some new attributes

* `req.time` : get the time where the request or response was captured

For the response object body, the following "Content-Encoding" type are honored :

* gzip

# FAQ

* `pcap_tools` found nothing in my pcap_files. Try to remove the wiresark profile, and re launch: `rm -rf $HOME/.wireshark/profiles/pcap_tools`.


