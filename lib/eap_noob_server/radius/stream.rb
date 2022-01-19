# frozen_string_literal: true

require 'socket'
require 'timeout'

module EAPNOOBServer
  module RADIUS
    # Class for handling one specific RADIUS stream.
    # This includes calculating the packet authenticators, message
    # authenticators, packet id.
    class Stream
      attr_reader :cur_pkt_id, :secret

      # Initialize a new stream
      # @param [String] host RADIUS-Server IP Address
      # @param [String] secret RADIUS Secret
      # @param [Hash] args
      # @option args [Integer] :port Custom Port (defaults to 1812)
      # @option args [Integer] :timeout Timout in seconds for answer (defaults to 60)
      def initialize(host, secret, **args)
        @host = host
        @secret = secret
        @port = args[:port] || 1812
        @state = nil
        @timeout = args[:timeout] || 60

        @cur_pkt_id = 0
      end

      # Open the UDP Socket
      # @return [void]
      def open
        @socket = UDPSocket.new
      end

      # Close the UDP Socket
      # @return [void]
      def close
        @socket.close
      end

      # Reopen the Socket. This also resets the packet identifier to 0.
      # @return [void]
      def reopen
        @socket.close
        @socket = UDPSocket.new
        @cur_pkt_id = 0
      end

      # Send a packet and wait for the reply
      # @param [EAPNOOBServer::RADIUS::Packet] pkt Packet to send
      # @return [EAPNOOBServer::RADIUS::Packet] Packet received
      # @raise [Timeout::Error] if the recv timed out
      # @raise [EAPNOOBServer::RADIUS::PacketError] if the Authenticator or MessageAuthenticator are invalid.
      def send_and_wait_for_reply(pkt)
        # First we set the Packet ID for this Stream.
        pkt.pktid = @cur_pkt_id

        # Then we add the State Attribute, if we have cached one
        pkt.attributes << { type: EAPNOOBServer::RADIUS::Packet::Attribute::STATE, data: @state } unless @state.nil?

        # Now we calculate the authenticator value and the Message Authenticator Attribute
        # We have to save the processed authenticator to validate the answer
        pkt.calculate_request!(@secret)
        msg_auth = pkt.authenticator

        # Now we send the packet to the RADIUS Server and wait for an answer
        @socket.send(pkt.to_bytestring, 0, @host, @port)

        text = nil
        Timeout.timeout(@timeout) do
          text, = @socket.recvfrom(255 * 255)
        end

        # We parse the Reply
        replypkt = EAPNOOBServer::RADIUS::Packet.parse_reply(text.unpack('C*'), @secret, msg_auth)
        unless replypkt.pktid == @cur_pkt_id
          # Something weird happened. The Reply should match the PktId of the original Packet
        end

        # When the parsing was completed we can increase the Packet ID
        @cur_pkt_id += 1
        @cur_pkt_id = 0 if @cur_pkt_id > 255

        # And now we also need to save the State variable, if there was any.
        state_attr = replypkt.get_attributes_by_type(EAPNOOBServer::RADIUS::Packet::Attribute::STATE)
        @state = if state_attr.empty?
                   nil
                 else
                   state_attr.first[:data]
                 end

        # And then finally we can return the reply packet.
        replypkt
      end
    end
  end
end
