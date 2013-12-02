module PcapTools

  class TcpStreamRebuilder

    def process_stream stream
      out = []
      current = nil
      stream[:data].each do |packet|
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
      {:index => stream[:index], :data => out}
    end

    def finalize
    end

  end

end