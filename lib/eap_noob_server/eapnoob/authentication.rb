# frozen_string_literal: true

module EAPNOOBServer
  module EAPNOOB
    # EAP-NOOB Authentication
    # @!attribute [r] peer_state
    #   @return [Integer] Peer State
    # @!attribute [r] server_state
    #   @return [Integer] Server State
    # @!attribute [r] cur_status
    #   @return [Symbol] Current status of the EAP authentication process
    class Authentication
      attr_reader :peer_state, :cur_status, :server_state

      ERROR_CODES = {
        invalid_nai: 1001,
        invalid_message_structure: 1002,
        invalid_data: 1003,
        unexpected_message_type: 1004,
        invalid_ecdhe_key: 1005,
        unwanted_peer: 2001,
        state_mismatch: 2003,
        unrecognized_oob_msg_identifier: 2004,
        unexpected_peer_identifier: 2005,
        no_mutually_supported_version: 3001,
        no_mutually_supported_cryptosuite: 3002,
        no_mutually_supported_oob_direction: 3003,
        hmac_verification_failure: 4001,
        application_specific_error: 5001,
        invalid_server_info: 5002,
        invalid_server_url: 5003,
        invalid_peer_info: 5004
      }.freeze

      SUPPORTED_ALGORITHMS = {
        1 => EAPNOOBServer::EAPNOOB::Crypto::Curve25519,
        2 => EAPNOOBServer::EAPNOOB::Crypto::NIST_P256
      }.freeze

      # Initialize a new EAP-NOOB authentication process
      # @param [String] identity NAI transmitted by the peer in the EAP-Identity message.
      # @param [EAPNOOBServer::EAP::Authentication] eap_auth reference
      def initialize(identity, eap_auth)
        @cur_status = :new
        @server_state = 0
        @eap_auth = eap_auth
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    { 'Type': 1 }.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
        @noob_attrs = { 'NAI': identity }
      end

      # Send out an EAP Error
      # @todo not yet implemented
      # @param [Symbol] error_code Error code to send
      # @param [String] msg Message to attach to the error
      def send_error(error_code, msg = nil)
        raise NotImplementedError, 'This is not yet implemented'
      end

      # Add a new request
      # @param [EAPNOOBServer::EAP::Packet] pkt EAP Packet to add
      def add_request(pkt)
        # First parse the JSON
        json = pkt.type_data.pack('C*')
        begin
          parsed = JSON.parse(json)
        rescue JSON::ParserError
          # send out error for JSON parsing error
          return
        end

        unless parsed['Type']
          # send out error for invalid data
          return
        end

        case parsed['Type']
        when 0
          # Error message
          # TODO: Handle error.
        when 1
          # PeerId and PeerState discovery
          send_error(:unexpected_message_type) unless @cur_status == :new
          handle_initial(parsed)
        when 2
          # Version, cryptosuite, and parameter negotiation
          send_error(:unexpected_message_type) unless @cur_status == :discovery_sent
          handle_param_negotiation(parsed)
        when 3
          # Exchange of ECDHE keys and nonces
          send_error(:unexpected_message_type) unless @cur_status == :parameters_sent
          handle_ecdhe_exchange(parsed)
        when 4
          # Indication to the peer that the server has not yet received an OOB message
          send_error(:unexpected_message_type) unless @cur_status == :waiting_sent
          handle_waiting(parsed)
        when 5
          # NoobId discovery
          send_error(:unexpected_message_type) unless @cur_status == :noobid_discovery_sent
          handle_noobid_discovery(parsed)
        when 6
          # Authentication and key confirmation with HMAC
          send_error(:unexpected_message_type) unless @cur_status == :hmac_sent
          handle_authentication_hmac(parsed)
        else
          # Unknown or yet unsupported type
          nil
        end
      end

      private

      # Handle PeerId and PeerState discovery packages
      # @param [Hash] parsed Content of the received JSON
      def handle_initial(parsed)
        @peer_state = parsed['PeerState'] || 1
        @peer_id = parsed['PeerId'] || generate_new_peer_id
        @noob_attrs['PeerId'] = @peer_id

        get_ephemeral_or_persistent_state

        EAPNOOBServer.logger.info("Server State: #{@server_state}")

        case @server_state
        when 0
          # Unregistered
          if @peer_state.between?(0, 2)
            execute_param_negotiation
          else
            send_error(:state_mismatch) # Incompatible status
          end
        when 1
          # Waiting for OOB
          case @peer_state
          when 0
            execute_param_negotiation
          when 1
            execute_waiting
          when 2
            execute_noobid_discovery
          else
            send_error(:state_mismatch) # Incompatible status
          end
        when 2
          # OOB Received
          case @peer_state
          when 0
            execute_param_negotiation
          when 1
            execute_authentication_hmac
          when 2
            execute_noobid_discovery
          else
            send_error(:state_mismatch) # Incompatible status
          end
        when 3, 4
          # Reconnecting/Registered
        else
          # Invalid state
          raise StandardError, 'Invalid server state'
        end
      end

      # Execute the initial exchange
      def execute_param_negotiation
        server_info = {
          'ServerURL': 'https://noob.namib.me/oob_submit'
        }
        return_val = {
          'Type': 2,
          'Vers': [1],
          'Cryptosuites': [1],
          'Dirs': 3,
          'PeerId': @peer_id,
          'ServerInfo': server_info
        }
        @noob_attrs['Vers'] = [1]
        @noob_attrs['Cryptosuites'] = [1]
        @noob_attrs['Dirs'] = 3
        @noob_attrs['ServerInfo'] = server_info

        @cur_status = :discovery_sent
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    return_val.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      # Handle Version, cryptosuite, and parameter negotiation packages
      # @param [Hash] parsed Content of the received JSON
      def handle_param_negotiation(parsed)
        send_error(:invalid_message_structure) unless parsed['Verp']
        send_error(:invalid_message_structure) unless parsed['Cryptosuitep']
        send_error(:invalid_message_structure) unless parsed['Dirp']
        send_error(:invalid_message_structure) unless parsed['PeerInfo']

        send_error(:no_mutually_supported_version) if parsed['Verp'] != 1
        send_error(:no_mutually_supported_cryptosuite) if parsed['Cryptosuitep'] != 1

        @noob_attrs['Verp'] = parsed['Verp']
        @noob_attrs['Cryptosuitep'] = parsed['Cryptosuitep']
        @noob_attrs['Dirp'] = parsed['Dirp']
        @noob_attrs['PeerInfo'] = parsed['PeerInfo']

        @crypto = Crypto::Curve25519.new

        execute_ecdhe_exchange
      end

      # Execute the ECDHE Key exchange
      def execute_ecdhe_exchange
        return_val = {
          'Type': 3,
          'PeerId': @peer_id
        }

        pk_s = @crypto.pks
        @noob_attrs['PKs'] = pk_s
        return_val['PKs'] = pk_s
        # Generate random Nonce
        n_s = SecureRandom.random_bytes(32)
        n_s_b = Base64.urlsafe_encode64(n_s, padding: false)
        @noob_attrs['Ns'] = n_s_b
        return_val['Ns'] = n_s_b

        @cur_status = :parameters_sent
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    return_val.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      # Handle ECDHE Key exchange
      # @param [Hash] parsed Content of the received JSON
      def handle_ecdhe_exchange(parsed)
        send_error(:invalid_message_structure) unless parsed['PKp']
        send_error(:invalid_message_structure) unless parsed['Np']

        @noob_attrs['PKp'] = parsed['PKp']
        @noob_attrs['Np'] = parsed['Np']

        key_det = parsed['PKp']
        send_error(:invalid_message_structure) unless key_det.is_a? Hash
        # send_error(:invalid_ecdhe_key) unless key_det['kty'] == 'OKP'
        send_error(:invalid_ecdhe_key) unless key_det['crv'] == 'X25519'
        send_error(:invalid_ecdhe_key) unless key_det['x']

        key_x = Base64.urlsafe_decode64(key_det['x'])

        @crypto.add_peer_key(key_x)
        @shared_secret = @crypto.calculate_shared_secret

        @eap_auth.send_failure

        @server_state = 1 # Waiting for OOB

        calculate_oob_message if @noob_attrs['Dirp'] == 2 || @noob_attrs['Dirp'] == 3

        @noob_attrs['server_state'] = @server_state

        save_ephemeral_state
      end

      def calculate_oob_message
        oob = EphemeralNoob.new
        oob.peer_id = @peer_id
        oob.noob = SecureRandom.random_bytes(32)
        noob_encoded = Base64.urlsafe_encode64(oob.noob, padding: false)
        oob.noob_id = @crypto.calculate_hash(['NoobId', noob_encoded].to_json)[0, 16]
        oob.hoob = calc_hoob(@crypto, @noob_attrs, 2, @peer_id, 0, noob_encoded)

        oob.save

        oob_msg = { peer_id: oob.peer_id, noob_id: oob.noob_id, noob: oob.noob, hoob: oob.hoob }
        puts oob_msg.inspect
      end

      # Calculate the Hoob
      # @param [Class] crypto Cryptography class used for calculating the hash
      # @param [Hash] attrs List of attributes for the current connection
      # @param [Integer] dir Direction of OOB-Message.
      #   1 for peer-to-server, 2 for server-to-peer.
      # @param [String] peer_id PeerId
      # @param [Integer] keying_mode Keying mode. Always 0 for HOOB-Calculation
      # @param [String] noob_encoded Base64URL-encoded NOOB
      # @todo For compatibility this uses the fixed value 'eap-noob.net' as NAI.
      def self.calc_hoob(crypto, attrs, dir, peer_id, keying_mode, noob_encoded) 
        input = [
          dir, # Dir
          attrs['Vers'],
          attrs['Verp'],
          peer_id, # PeerId
          attrs['Cryptosuites'],
          attrs['Dirs'],
          attrs['ServerInfo'],
          attrs['Cryptosuitep'],
          attrs['Dirp'],
          'eap-noob.net', # attrs['NAI'],
          attrs['PeerInfo'],
          keying_mode, # Keying mode
          attrs['PKs'],
          attrs['Ns'],
          attrs['PKp'],
          attrs['Np'],
          noob_encoded # NOOB (Base64url encoded)
        ].to_json
        EAPNOOBServer.logger.info "Input to HOOB Calculation: #{input}"
        crypto.calculate_hash(input)[0, 16]
      end

      def execute_waiting
        return_val = {
          'Type': 4,
          'PeerId': @peer_id
        }
        @cur_status = :waiting_sent
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    return_val.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      def handle_waiting(parsed)
        @eap_auth.send_failure
      end

      def execute_noobid_discovery
        return_val = {
          'Type': 5,
          'PeerId': @peer_id
        }
        @cur_status = :noobid_discovery_sent
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    return_val.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      def handle_noobid_discovery(parsed)
        # TODO Not yet implemented
      end

      def execute_authentication_hmac
        # TODO Not yet implemented
      end

      def handle_authentication_hmac(parsed)
        # TODO Not yet implemented
      end

      # Get the ephemeral or persistent state
      # @todo not yet implemented completely
      def get_ephemeral_or_persistent_state
        # TODO: Not yet implemented
        @eph = EphemeralState.find_by(peer_id: @peer_id)
        unless @eph.nil?
          @noob_attrs = JSON.parse(@eph.noob_attrs)
          @server_state = @noob_attrs['server_state']
          @shared_secret = @eph.shared_secret
        end

        # TODO: Persistent Storage
      end

      # Save the ephemeral state after the initial handshake
      def save_ephemeral_state
        state = @eph || EphemeralState.new
        state.peer_id = @peer_id
        state.noob_attrs = @noob_attrs.to_json
        state.shared_secret = @shared_secret
        state.save
      end

      # Generate a new random PeerId
      def generate_new_peer_id
        ((('a'..'z').to_a + ('0'..'9').to_a + %w[- .]) * 16).sample(16).join ''
      end

      def key_generation
        # See src/eap_common/eap_noob_common.c L. 633
      end
    end
  end
end
