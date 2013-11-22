
class PacketFu::Packet

  attr_accessor :timestamp #  access to pcap timestamp

  # Parse() creates the correct packet type based on the data, and returns the apporpiate
  # Packet subclass object. 
  #
  # There is an assumption here that all incoming packets are either EthPacket
  # or InvalidPacket types. This will be addressed pretty soon.
  #
  # If application-layer parsing is /not/ desired, that should be indicated explicitly
  # with an argument of  :parse_app => false. Otherwise, app-layer parsing will happen.
  #
  # It is no longer neccisary to manually add packet types here.
  def self.parse(packet=nil,args={})
    parse_app = true if(args[:parse_app].nil? or args[:parse_app])
    str = packet
    if packet.is_a? Hash
      timestamp = packet.keys.first
      str = packet[timestamp]
      timestamp = PacketFu::Timestamp.new().read(String.new(timestamp))
      timestamp = Time.at(timestamp.sec.value, timestamp.usec.value)
    end
    force_binary(str)
    if parse_app
      classes = PacketFu.packet_classes.select {|pclass| pclass.can_parse? str}
    else
      classes = PacketFu.packet_classes.select {|pclass| pclass.can_parse? str}.reject {|pclass| pclass.layer_symbol == :application}
    end
    p = classes.sort {|x,y| x.layer <=> y.layer}.last.new
    parsed_packet = p.read(str, args)
    parsed_packet.timestamp = timestamp if packet.is_a? Hash
    parsed_packet
  end

end