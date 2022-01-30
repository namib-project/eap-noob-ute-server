# frozen_string_literal: true

module EAPNOOBServer
  module RADIUS
    # RADIUS Server
    # @!attribute [r] streams
    #   @return [Array] List of known RADIUS streams
    class Server
      attr_reader :streams

      # Initialize a new server
      # @param [String] secret RADIUS Secret
      # @param [Hash] args
      # @option args [Integer] :port Custom Port (defaults to 1812)
      # @option args [Integer] :timeout Timeout for answers (defaults to 60)
      # @option args [String] :bind IP Address to bind to (defaults to 0.0.0.0)
      # @option args [Boolean] :status_server Activates Status-Server functionality (RFC5997) (defaults to true)
      # @todo Currently the server does not support different secrets for different clients.
      #   This should be extended in a future version, which will probably not be backwards compatible.
      def initialize(secret, **args)
        @socket = UDPSocket.new
        bind = args[:bind] || '0.0.0.0'
        port = args[:port] || 1812
        @timeout = args[:timeout] || 60
        @status_server = args[:status_server].nil? ? true : args[:status_server]
        @socket.bind(bind, port)
        @streams = {}
        @secret = secret
        @listen_thread = Thread.new do
          loop do
            read_packet(@socket.recvfrom(256 * 256))
          rescue StandardError => e
            warn 'Error caught.', e
            warn e.backtrace
          end
        end
      end

      # Read a packet received from the socket
      # @todo Retransmissions are not yet handled.
      #   If a response to a packet is already sent, then the answer should be retransmitted.
      def read_packet(pkt)
        msg = pkt[0]
        sender_info = pkt[1]
        family = sender_info[0]
        src_port = sender_info[1]
        src_ip = sender_info[3]

        rad_pkt = RADIUS::Packet.parse_request(msg.unpack('C*'), @secret)

        if @status_server
          if rad_pkt.type == RADIUS::Packet::Type::STATUSSERVER
            reply_pkt = RADIUS::Packet.new(RADIUS::Packet::Type::ACCEPT, rad_pkt.pktid)
            send_reply(reply_pkt, [src_ip, src_port], rad_pkt.authenticator, nil, nil)
            return
          end
        end

        state = rad_pkt.get_attributes_by_type(RADIUS::Packet::Attribute::STATE).map { |attr| attr[:data].pack('C*') }

        key = state.first

        stream = @streams[key]
        if stream
          @streams.delete key
          stream.add_request(rad_pkt)
        else
          Authentication.new(rad_pkt, [src_ip, src_port], self)
        end
      end

      # Send a reply to the peer
      # @param [EAPNOOBServer::RADIUS::Packet] rad_pkt RADIUS Packet to be sent out
      # @param [Array] dest Destination as array of ip address and port
      # @param [Array] request_auth Value of the authenticator field in the previous request
      # @param [String] state Value of the State attribute to match the following request
      # @param [EAPNOOBServer::RADIUS::Authentication] radius_auth Instance of the current authentication process
      def send_reply(rad_pkt, dest, request_auth, state, radius_auth)
        @streams[state] = radius_auth unless state.nil? || radius_auth.nil?
        rad_pkt.calculate_reply!(@secret, request_auth)
        @socket.send rad_pkt.to_bytestring, 0, dest[0], dest[1]
      end

      # Send an accept to the peer
      # @param [EAPNOOBServer::RADIUS::Packet] rad_pkt RADIUS Packet to be sent out
      # @param [Array] dest Destination as array of ip address and port
      # @param [Array] request_auth Value of the authenticator field in the previous request
      # @param [Array] recv_key MPPE-Recv-Key as array of bytes
      # @param [Array] send_key MPPE-Send-Key as array of bytes
      def send_accept(rad_pkt, dest, request_auth, recv_key, send_key)
        rad_pkt.add_cryptographic_key(16, request_auth, @secret, send_key)
        rad_pkt.add_cryptographic_key(17, request_auth, @secret, recv_key)
        rad_pkt.calculate_reply!(@secret, request_auth)
        @socket.send rad_pkt.to_bytestring, 0, dest[0], dest[1]
      end
    end
  end
end
