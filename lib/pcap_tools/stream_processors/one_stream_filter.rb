module PcapTools

  class TcpOneStreamFilter

    def initialize target
      @target = target
    end

    def process_stream stream
      return nil if @target && stream[:index] != @target
      stream
    end

    def finalize
    end

  end

end