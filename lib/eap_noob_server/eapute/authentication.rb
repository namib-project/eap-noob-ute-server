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
        ERROR = 0
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

      module ErrorCodes
        INVALID_MESSAGE_STRUCTURE = 1
        UNEXPECTED_MESSAGE_TYPE = 2
        MISSING_MANDATORY_FIELD = 3
        VERSION_MISMATCH = 4
        CIPHER_MISMATCH = 5
        UNKNOWN_OOB_MSG = 6
        UNKNOWN_PEER = 7
      end

      # Initialize a new EAP-UTE authentication process
      # @param [String] identity NAI transmitted by the peer in the EAP-Identity message.
      # @param [EAPNOOBServer::EAP::Authentication] eap_auth reference
      def initialize(identity, eap_auth)
        @cur_status = :new
        @chosen_exchange = :none
        @server_state = 0
        @eap_auth = eap_auth
        @identity = identity
        @hash_input = ""

        send_server_greeting
      end

      def send_server_greeting
        msg = {
          MessageField::VERSIONS => [1],
          MessageField::CIPHERS => [[4],[-16]],
          MessageField::SERVER_INFO => {},
          MessageField::DIRECTIONS => 0x03
        }
        send_reply(MessageType::SERVER_GREETING, msg.to_cbor)
        @cur_status = :server_greeting_sent
      end

      def send_error(error_code)
        raise NotImplementedError, 'This is not yet implemented'
      end

      def add_request(pkt)
        warn 'EAP-UTE: received request'
        # First unpack the packet
        data = pkt.type_data.pack('C*')

        msg_type,nextbytes = CBOR.decode_with_rest(data)

        cbor_data_b,nextbytes = CBOR.decode_with_rest(nextbytes)
        cbor_data = CBOR.decode(cbor_data_b)

        @hash_input += msg_type.to_cbor + cbor_data_b.to_cbor

        additional_data,nextbytes = CBOR.decode_with_rest(nextbytes) unless nextbytes.empty?

        if nextbytes.length != 0
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE)
          return
        end

        warn "EAP-UTE: Message type: #{msg_type}"
        case @cur_status
        when :server_greeting_sent
          case msg_type
          when MessageType::CLIENT_GREETING
            @chosen_exchange = :initial_or_version_upgrade
            handle_client_greeting(cbor_data, additional_data)
          when MessageType::CLIENT_COMPLETION_REQUEST
            @chosen_exchange = :completion_or_static_reconnect
            handle_client_completion_request(cbor_data, additional_data)
          when MessageType::CLIENT_KEYSHARE
            @chosen_exchange = :dynamic_reconnect
            handle_client_keyshare(cbor_data, additional_data)
          else
            send_error(ErrorCodes::UNEXPECTED_MESSAGE_TYPE)
          end
          return
        when :server_completion_response
          case msg_type
          when MessageType::CLIENT_FINISHED
            handle_client_finished(cbor_data, additional_data)
          else
            send_error(ErrorCodes::UNEXPECTED_MESSAGE_TYPE)
          end
          return
        else
          case msg_type
          when MessageType::CLIENT_FINISHED
            handle_client_finished(cbor_data, additional_data)
          when MessageType::ERROR
            # TODO Log the error message
            @eap_auth.send_failure and return
          else
            send_error(ErrorCodes::UNEXPECTED_MESSAGE_TYPE)
          end
        end
      end

      def ecdhe_exchange
        warn 'EAP-UTE: Calculate ECDHE Shared secret'
        crypto = EAPUTE::Crypto::Curve25519.new
        crypto.add_peer_key @key_peer
        @key_server = crypto.pks
        @shared_secret = crypto.calculate_shared_secret

        warn "Shared secret: #{@shared_secret.unpack('H*')}"
      end

      def send_server_keyshare
        warn 'EAP-UTE: Constructing server keyshare'
        to_return = {}
        if @chosen_exchange == :initial
          generate_new_peer_id
          to_return[MessageField::PEER_IDENTIFIER] = @peer_id
        end
        to_return[MessageField::KEY_SERVER] = @key_server

        @nonce_server = SecureRandom.random_bytes(32)
        to_return[MessageField::NONCE_SERVER] = @nonce_server.b

        if @chosen_exchange == :upgrade
          key_derivation
          to_return[MessageField::MAC_SERVER] = nil
        end
        # TODO if Upgrade exchange include MAC
        send_reply(MessageType::SERVER_KEYSHARE, to_return.to_cbor)
        @cur_status = :server_keyshare_sent
      end

      def send_server_completion_response
        @nonce_server = SecureRandom.random_bytes(32)

        key_derivation

        to_return = {}
        to_return[MessageField::NONCE_SERVER] = @nonce_server.b
        to_return[MessageField::OOB_ID] = @oob_msg.oob_id if @oob_msg.direction == 1
        to_return[MessageField::MAC_SERVER] = nil

        payload = MessageType::SERVER_COMPLETION_RESPONSE.to_cbor
        payload += to_return.to_cbor.b.to_cbor

        @hash_input += payload

        mac_calculation

        mac = {}
        mac[MessageField::MAC_SERVER] = @mac_s

        send_reply(MessageType::SERVER_COMPLETION_RESPONSE, to_return.to_cbor, mac.to_cbor)
      end

      def handle_client_greeting(cbor, _additional)
        #warn "EAP-UTE: Content of the payload: #{cbor}"
        unless cbor[MessageField::VERSION]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::VERSION].is_a? Integer
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        unless cbor[MessageField::VERSION] == 1
          # TODO currently fixed on version 1
          send_error(ErrorCodes::VERSION_MISMATCH) and return
        end

        unless cbor[MessageField::CIPHER]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::CIPHER].is_a? Array
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        unless cbor[MessageField::CIPHER].length == 2
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        unless cbor[MessageField::CIPHER][0] == 4
          # ECDHE curve currently fixed on 4 (X25519)
          send_error(ErrorCodes::CIPHER_MISMATCH) and return
        end
        unless cbor[MessageField::CIPHER][1] == -16
          # Hash algorithm currently fixed on -16 (SHA-256)
          send_error(ErrorCodes::CIPHER_MISMATCH) and return
        end

        if cbor[MessageField::PEER_IDENTIFIER]
          # TODO: Lookup peerid.
          #   If persistent -> version/cipher upgrade exchange
          #   else -> initial exchange
        else
          @chosen_exchange = :initial
        end

        unless cbor[MessageField::NONCE_PEER]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::NONCE_PEER].is_a? String
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        # TODO: Maybe check if the string is encoded as binary

        @nonce_peer = cbor[MessageField::NONCE_PEER]

        unless cbor[MessageField::KEY_PEER]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::KEY_PEER].is_a? Hash
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        unless cbor[MessageField::KEY_PEER][-1]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::KEY_PEER][-1].is_a? Integer
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        unless cbor[MessageField::KEY_PEER][-2]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::KEY_PEER][-2].is_a? String
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        # TODO: maybe check if the string is encoded as binary
        @key_peer = cbor[MessageField::KEY_PEER][-2]

        ecdhe_exchange

        send_server_keyshare
      end

      def handle_client_keyshare(cbor, additional)

      end

      def handle_client_completion_request(cbor, _additional)
        #warn "EAP-UTE: Content of the payload: #{cbor}"
        unless cbor[MessageField::PEER_IDENTIFIER]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::PEER_IDENTIFIER].is_a? String
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        @peer_id = cbor[MessageField::PEER_IDENTIFIER]

        state = EphemeralAssociation.find_by(peer_id: @peer_id)
        if(state.nil?)
          send_error(ErrorCodes::UNKNOWN_PEER) and return
        end
        @shared_secret = state.shared_secret
        @old_hash = state.msg_hash

        unless cbor[MessageField::NONCE_PEER]
          send_error(ErrorCodes::MISSING_MANDATORY_FIELD) and return
        end
        unless cbor[MessageField::NONCE_PEER].is_a? String
          send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
        end
        @nonce_peer = cbor[MessageField::NONCE_PEER]

        if cbor[MessageField::OOB_ID]
          unless cbor[MessageField::OOB_ID].is_a? String
            send_error(ErrorCodes::INVALID_MESSAGE_STRUCTURE) and return
          end
          @oob_id = cbor[MessageField::OOB_ID]
          @oob_msg = OutOfBand.find_by(oob_id: @oob_id, direction: 2)
          send_error(ErrorCodes::UNKNOWN_OOB_MSG) and return if @oob_msg.nil?
        end

        # TODO: Here a determination must be made between completion and reconnect exchanges

        if @oob_msg.nil?
          @oob_msg = OutOfBand.find_by(peer_id: @peer_id, direction: 1)
          if @oob_msg.nil?
            warn 'No OOB messages for the given peer id found'
            @eap_auth.send_failure and return
          end
        end

        @chosen_exchange = :completion

        send_server_completion_response
      end

      def handle_client_finished(cbor, additional)
        warn 'Handling client finished'
        warn "Hash was: #{OpenSSL::Digest::SHA256.digest(@hash_input).unpack('H*')}"
        if @chosen_exchange == :initial
          save_ephemeral_state
          @eap_auth.send_failure
        elsif @chosen_exchange == :completion
          save_persistent_state
          # TODO: Send access accept
        else
          # TODO: Not yet implemented.
          #   Reconnect or Upgrade exchange
          @eap_auth.send_failure
        end
      end

      def key_derivation
        complete_key = kdf(@shared_secret,@nonce_peer,@nonce_server,@oob_msg.nonce, 320)

        warn "KDF key: #{complete_key.unpack1('H*')}"
        @kdf_MSK = complete_key[0,64]
        @kdf_EMSK = complete_key[64,64]
        @kdf_AMSK = complete_key[128,64]
        @kdf_MethodId = complete_key[192,32]
        @kdf_MAC_s = complete_key[224,32]
        @kdf_MAC_p = complete_key[256,32]
        @kdf_AssociationKey = complete_key[288,32]
      end

      def kdf(z, party_u_info, party_v_info, supp_priv_info, out_len)
        kdf_input = "#{z}EAP-UTE#{party_u_info}#{party_v_info}#{supp_priv_info || ''}"
        output = ''
        ctr = 1
        warn "KDF Input (#{kdf_input.length}):"
        warn kdf_input.unpack1('H*')
        while output.length < out_len
          output += OpenSSL::Digest::SHA256.digest([ctr].pack('N') + kdf_input)
          ctr += 1
        end
        output[0, out_len]
      end

      def mac_calculation
        mac_input = @old_hash
        mac_input += OpenSSL::Digest::SHA256.digest(@hash_input)
        warn "Key S: #{@kdf_MAC_s.unpack1('H*')}"
        warn "Msg S: #{"\x02#{mac_input}".unpack1('H*')}"
        @mac_s = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @kdf_MAC_s, "\x02#{mac_input}")
        warn "MAC S: #{@mac_s.unpack1('H*')}"

        warn "Key P: #{@kdf_MAC_p.unpack1('H*')}"
        warn "Msg P: #{"\x01#{mac_input}".unpack1('H*')}"
        @mac_p = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @kdf_MAC_p, "\x01#{mac_input}")
        warn "MAC P: #{@mac_p.unpack1('H*')}"
      end

      def generate_new_peer_id
        @peer_id = SecureRandom.bytes(16)
      end

      def save_ephemeral_state
        state = EphemeralAssociation.new
        state.peer_id = @peer_id
        state.msg_hash = OpenSSL::Digest::SHA256.digest(@hash_input)
        state.hash_input = @hash_input
        state.shared_secret = @shared_secret
        state.save
      end

      def save_persistent_state
        raise NotImplementedError
      end
      # Wrapper to for sending replies.
      # Adds the packet to the hmac tmp save for later calculation and appends the correct mac tag, if instructed
      def send_wrapper(msg_type, cbr, calc_mac: false)
        pkt_history_add = [msg_type].pack('C')
        parsed = cbr.to_deterministic_cbor
        len = parsed.length
        @pkt_history += [msg_type].pack('C') + len.pack('n') + parsed

        if calc_mac
          mac_calculation
        end
      end

      # Send Reply
      # @param [Fixnum] msg_type Message type
      # @param [String] reply Content of the Reply packet as hash
      # @param [String|NilClass] additional additional data to append, e.g. HMAC value
      def send_reply(msg_type, reply, additional=nil)
        payload = msg_type.to_cbor
        payload += reply.b.to_cbor

        @hash_input += payload

        payload += additional.b.to_cbor unless additional.nil?

        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::UTE,
                                    payload.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end
    end
  end
end