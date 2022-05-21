# frozen_string_literal: true

module EAPNOOBServer
  module EAPUTE
    class Authentication

      module StateMachine
        UNREGISTERED = 0
        WAITING_FOR_OOB = 1
        OOB_RECEIVED = 2
        REGISTERED = 3
      end

      module MessageType
        SERVER_GREETING = 1
        CLIENT_GREETING = 2
        SERVER_KEYSHARE = 3
        CLIENT_FINISHED = 4
        CLIENT_COMPLETION_REQUEST = 5
        SERVER_COMPLETION_RESPONSE = 6
        CLIENT_KEYSHARE = 7
      end

      module MessageField
        VERSIONS = 1
        VERSION = 2
        CIPHERS = 3
        CIPHER = 4
        DIRECTIONS = 5
        DIRECTION = 6
        SERVER_INFO = 7
        PEER_INFO = 8
        NONCE_PEER = 9
        NONCE_SERVER = 10
        KEY_PEER = 11
        KEY_SERVER = 12
        MAC_SERVER = 13
        MAC_PEER = 14
        PEER_IDENTIFIER = 15
        OOB_ID = 16
        RETRY_INTERVAL = 17
        ADDITIONAL_SERVER_INFO = 18
      end

      # Initialize a new EAP-UTE authentication process
      # @param [String] identity NAI transmitted by the peer in the EAP-Identity message.
      # @param [EAPNOOBServer::EAP::Authentication] eap_auth reference
      def initialize(identity, eap_auth)
        @cur_status = :new
        @server_state = 0
        @eap_auth = eap_auth
      end

      def execute_server_greeting
        msg = {
          MessageField::VERSIONS => [1],
          MessageField::CIPHERS => [4],
          MessageField::SERVER_INFO => {},
          MessageField::DIRECTIONS => 0x03
        }
        send_reply(msg)
      end

      def add_request(pkt)
        # TODO
      end

      # Send Reply
      # @param [Hash] reply Content of the Reply packet as hash
      def send_reply(reply)
        repl_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                   @eap_auth.next_identifier,
                                   EAP::Packet::Type::UTE,
                                   reply.to_cbor.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end
    end
  end
end