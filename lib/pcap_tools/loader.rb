require 'popen4'
require 'ox'
require 'fileutils'

module PcapTools

  module Loader

  	class MyParser < ::Ox::Sax

  		def initialize block
				@current_packet_index = 0
				@current_packet = nil
				@current_processing = nil
				@current_proto_name = nil
				@current_field_name = nil
				@block = block
			end

			def attr name, value
				if @current_processing == :proto && name == :name
					@current_proto_name = value
					@current_packet[:protos] << value
				elsif @current_processing == :field && name == :name
					@current_field_name = value
					# p @current_field_name
				elsif name == :show
					if @current_proto_name == "geninfo" && @current_field_name == "timestamp"
						@current_packet[:time] = Time.parse value
					elsif @current_proto_name == "ip" && @current_field_name == "ip.src"
						@current_packet[:from] = value
					elsif @current_proto_name == "ip" && @current_field_name == "ip.dst"
						@current_packet[:to] = value
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.len"
						@current_packet[:size] = value.to_i
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.stream"
						@current_packet[:stream] = value.to_i
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.srcport"
						@current_packet[:from_port] = value.to_i
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.dstport"
						@current_packet[:to_port] = value.to_i
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.flags.fin"
						@current_packet[:tcp_flags][:fin] = value == "1"
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.flags.reset"
						@current_packet[:tcp_flags][:rst] = value == "1"
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.flags.ack"
						@current_packet[:tcp_flags][:ack] = value == "1"
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.flags.syn"
						@current_packet[:tcp_flags][:syn] = value == "1"
					end
				elsif name == :value
					if @current_proto_name == "fake-field-wrapper" && @current_field_name == "data"
						@current_packet[:data] = [value].pack("H*")
					elsif @current_proto_name == "tcp" && @current_field_name == "tcp.segment_data"
						@current_packet[:data] = [value].pack("H*")
					end
				end
			end

			def start_element name, attrs = []
				if name == :packet
					@current_packet = {
						:tcp_flags => {},
						:packet_index => @current_packet_index,
						:protos => [],
					}
				elsif name == :proto
					@current_processing = :proto
				elsif name == :field
					@current_processing = :field
				elsif name == :pdml
				else
					raise "Unknown element [#{name}]"
				end
			end

			def end_element name
				if name == :packet
					# p @current_packet
					raise "No data found in packet #{@current_packet_index}, protocols found #{@current_packet[:protos]}" if @current_packet[:data].nil? && @current_packet[:size] > 0
					@current_packet.delete :protos
					@block.call @current_packet_index, @current_packet
					@current_packet_index += 1
				end
			end

  	end

    def self.load_file f, options = {}, &block
    	tshark_executable = options[:tshark] || "tshark"
    	disabled_protocols = options[:disabled_protocols] || ["http"]
    	profile_name = "pcap_tools"
    	profile_dir = "#{ENV['HOME']}/.wireshark/profiles/#{profile_name}"
    	FileUtils.mkdir_p profile_dir
    	File.open("#{profile_dir}/disabled_protos", "w") {|io| io.write(disabled_protocols.join("\n") + "\n")}
    	status = POpen4::popen4("#{tshark_executable} -n -C #{profile_name} -T pdml -r #{f}") do |stdout, stderr, stdin, pid|
    		Ox.sax_parse(MyParser.new(block), stdout)
    	end
    	raise "Tshark execution error with file #{f}" unless status.exitstatus == 0
   end

  end

end
