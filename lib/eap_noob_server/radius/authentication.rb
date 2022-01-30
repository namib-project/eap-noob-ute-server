# frozen_string_literal: true

module EAPNOOBServer
  module RADIUS
    # A RADIUS Authentication communication
    class Authentication
      attr_reader :pkt_stream, :peer_ipaddr, :peer_port, :eap_authentication, :current_pkt_id, :server

      # Initialize a new authentication
      # @param [EAPNOOBServer::RADIUS::Packet] firstpkt Initial RADIUS Packet
      # @param [Array] sender_info IP Address and Source Port of the request.
      # @param[EAPNOOBServer::RADIUS::Server] server Instance of the RADIUS server class to send the replies out over
      def initialize(firstpkt, sender_info, server)
        @pkt_stream = [firstpkt]
        @peer_ipaddr = sender_info[0]
        @peer_port   = sender_info[1]

        @server = server

        @current_pkt_id = firstpkt.pktid

        @eap_authentication = EAP::Authentication.new(firstpkt, self)
      end

      # Process a new request
      # @param [EAPNOOBServer::RADIUS::Packet] pkt New RADIUS packet to add
      def add_request(pkt)
        @pkt_stream << pkt
        @current_pkt_id = pkt.pktid
        @eap_authentication.add_request(pkt)
      end

      # Send a EAP response
      # @param [Array] eap_attributes EAP Attributes as array
      def send_reply(eap_attributes)
        reply_pkt = RADIUS::Packet.new(RADIUS::Packet::Type::CHALLENGE, @current_pkt_id)
        reply_pkt.add_attributes eap_attributes
        state = Array.new(32) { rand(0..255) }
        state_str = state.pack('C*')
        reply_pkt.add_attributes [{
          type: RADIUS::Packet::Attribute::STATE,
          data: state
        }]

        lastpkt = @pkt_stream.last
        raise StandardError, 'Packet not a RADIUS packet' unless lastpkt.is_a? RADIUS::Packet

        @pkt_stream << reply_pkt

        @server.send_reply(reply_pkt, [@peer_ipaddr, @peer_port], lastpkt.authenticator, state_str, self)
      end

      # Send an accept message
      # @param [Array] eap_attributes EAP Attributes as array
      # @param [Array] recv_key MPPE-Recv-Key as array of bytes
      # @param [Array] send_key MPPE-Send-Key as array of bytes
      def send_accept(eap_attributes, recv_key, send_key)
        reply_pkt = RADIUS::Packet.new(RADIUS::Packet::Type::ACCEPT, @current_pkt_id)
        reply_pkt.add_attributes eap_attributes

        lastpkt = @pkt_stream.last
        raise StandardError, 'Packet not a RADIUS packet' unless lastpkt.is_a? RADIUS::Packet

        @pkt_stream << reply_pkt

        @server.send_accept(reply_pkt, [@peer_ipaddr, @peer_port], lastpkt.authenticator, recv_key, send_key)
      end

      # Send a reject message
      # @param [Array] eap_attributes EAP Attributes as array
      def send_reject(eap_attributes)
        reply_pkt = RADIUS::Packet.new(RADIUS::Packet::Type::REJECT, @current_pkt_id)
        reply_pkt.add_attributes eap_attributes

        lastpkt = @pkt_stream.last
        raise StandardError, 'Packet not a RADIUS packet' unless lastpkt.is_a? RADIUS::Packet

        @pkt_stream << reply_pkt

        @server.send_reply(reply_pkt, [@peer_ipaddr, @peer_port], lastpkt.authenticator, nil, self)
      end

    end
  end
end
