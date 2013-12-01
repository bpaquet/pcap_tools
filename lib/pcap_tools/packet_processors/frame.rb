
module PcapTools

	class FrameProcessor

		def initialize
			@counter = 0
		end

		def inject index, packet
			@counter += 1
		end

		def finalize
			puts "Number of frames : #{@counter}"
		end

	end

end
