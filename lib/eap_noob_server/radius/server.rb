
module EAPNOOBServer
  module RADIUS
    class Server

      # List of known RADIUS streams
      attr_reader :streams

      # Initialize a new stream
      # @param [String] secret RADIUS Secret
      # @param [Hash] args
      # @option args [Integer] :port Custom Port (defaults to 1812)
      # @option args [Integer] :timeout Timeout for answers (defaults to 60)
      # @option args [String] :bind IP Address to bind to (defaults to 0.0.0.0)
      # @todo Currently the server does not support different secrets for different clients.
      #   This should be extended in a future version, which will probably not be backwards compatible.
      def initialize(secret, **args)
        @socket = UDPSocket.new
        bind = args[:bind] || '0.0.0.0'
        port = args[:port] || 1812
        @timeout = args[:timeout] || 60
        @socket.bind(bind, port)
        @streams = {}
        @secret = secret
        @listen_thread = Thread.new do
          read_packet(@socket.recvfrom)
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

        rad_pkt = RADIUS::Packet.parse_request(msg, @secret)

        key = { id: rad_pkt, src: [src_ip, src_port] }

        stream = @streams[key]
        if stream
          @streams.delete key
          Thread.new { stream.add_request(rad_pkt) }
        else
          Thread.new { Authentication.new(rad_pkt, [src_ip, src_port]) }
        end
      end
    end
  end
end
