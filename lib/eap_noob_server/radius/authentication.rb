module EAPNOOBServer
  module RADIUS
    # A RADIUS Authentication communication
    class Authentication
      attr_reader :pkt_stream, :peer_ipaddr, :peer_port

      # Initialize a new authentication
      # @param [EAPNOOBServer::RADIUS::Packet] firstpkt Initial RADIUS Packet
      # @param [Array] sender_info IP Address and Source Port of the request.
      def initialize(firstpkt, sender_info)
        @pkt_stream = [firstpkt]
        @peer_ipaddr = sender_info[0]
        @peer_port   = sender_info[1]
      end

      # Process a new request
      # @param [EAPNOOBServer::RADIUS::Packet] pkt New RADIUS packet to add
      def add_request(pkt)
        # TODO
      end
    end
  end
end
