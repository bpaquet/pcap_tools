require 'time'

module PcapTools

  class TcpProcessor

    def initialize
      @streams = {}
      @stream_processors = []
    end

    def add_stream_processor processor
      @stream_processors << processor
    end

    def inject index, packet
      stream_index = packet[:stream]
      if stream_index
        if packet[:tcp_flags][:syn] && packet[:tcp_flags][:ack] === false
          @streams[stream_index] = {
            :first => packet,
            :data => [],
            :tcp_lost_segment => false,
          }
        elsif packet[:tcp_flags][:fin] || packet[:tcp_flags][:rst]
          if @streams[stream_index]
            current = {:index => stream_index, :data => @streams[stream_index][:data]}
            @stream_processors.each do |p|
              current = p.process_stream current
              break unless current
            end
            @streams.delete stream_index
          end
        else
          if @streams[stream_index]
            packet[:type] = (packet[:from] == @streams[stream_index][:first][:from] && packet[:from_port] == @streams[stream_index][:first][:from_port]) ? :out : :in
            packet.delete :tcp_flags
            @streams[stream_index][:data] << packet if packet[:size] > 0
            if packet[:tcp_lost_segment]
              @streams.delete stream_index
              $stderr.puts "Ignoring tcp stream #{stream_index}, tcp segments are missing"
            end
          end
        end
      end
    end

    def finalize
      @stream_processors.each do |p|
        p.finalize
      end
    end

  end

end