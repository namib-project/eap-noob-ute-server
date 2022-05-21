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

      module StateMachine
        UNREGISTERED = 0
        WAITING_FOR_OOB = 1
        OOB_RECEIVED = 2
        RECONNECTING = 3
        REGISTERED = 4
      end

      # Initialize a new EAP-NOOB authentication process
      # @param [String] identity NAI transmitted by the peer in the EAP-Identity message.
      # @param [EAPNOOBServer::EAP::Authentication] eap_auth reference
      def initialize(identity, eap_auth)
        @cur_status = :new
        @server_state = 0
        @eap_auth = eap_auth

        return_val = { 'Type': 1 }

        send_reply return_val
        @noob_attrs = { 'NAI' => identity }
      end

      # Send out an EAP Error
      # @todo not yet implemented
      # @param [Symbol] _error_code Error code to send
      # @param [String] _msg Message to attach to the error
      def send_error(_error_code, _msg = nil)
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
          # TODO: Handle error
          warn "Received Error code #{parsed['ErrorCode']}"
          @eap_auth.send_failure
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
        when 7
          # Version, cryptosuite, and parameter negotiation
          send_error(:unexpected_message_type) unless @cur_status == :reconnect_negotiation_sent
          handle_reconnect_version_negotiation(parsed)
        when 8
          # Exchange of ECDHE keys and nonces
          send_error(:unexpected_message_type) unless @cur_status == :reconnect_parameter_sent
          handle_reconnect_echde_exchange(parsed)
        when 9
          # Authentication and key confirmation with HMAC
          send_error(:unexpected_message_type) unless @cur_status == :reconnect_hmac_sent
          handle_reconnect_hmac_exchange(parsed)
        else
          # Unknown or yet unsupported type
          nil
        end
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
      def self.calc_hoob(crypto, attrs, dir, peer_id, keying_mode, noob_encoded, nai='eap-noob.net')
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
          # nai || '',
          attrs['NAI'],
          attrs['PeerInfo'],
          keying_mode, # Keying mode
          attrs['PKs'],
          attrs['Ns'],
          attrs['PKp'],
          attrs['Np'],
          noob_encoded # NOOB (Base64url encoded)
        ].to_json
        warn "NOOB Attributes: #{attrs}"
        warn "HOOB Input: #{input}"
        base = crypto
        base = crypto.class unless crypto.is_a? Class
        base.calculate_hash(input)[0, 16]
      end

      def self.generate_hash_input(attrs, dir, peer_id, keying_mode, noob_encoded, rekeying,  nai='eap-noob.net')
        [
          dir,
          attrs['Vers'],
          attrs['Verp'],
          peer_id,
          attrs['Cryptosuites'],
          attrs['Dirs'] || '',
          attrs['ServerInfo'] || '',
          attrs['Cryptosuitep'],
          attrs['Dirp'] || '',
          # nai || '',
          attrs['NAI'],
          attrs['PeerInfo'] || '',
          keying_mode,
          (rekeying ? attrs['PKs2'] || '' : attrs['PKs']),
          (rekeying ? attrs['Ns2'] : attrs['Ns']),
          (rekeying ? attrs['PKp2'] || '' : attrs['PKp']),
          (rekeying ? attrs['Np2'] : attrs['Np']),
          noob_encoded || ''
        ].to_json
      end

      private

      # Handle PeerId and PeerState discovery packages
      # @param [Hash] parsed Content of the received JSON
      def handle_initial(parsed)
        @peer_state = parsed['PeerState'] || 1
        @peer_id = parsed['PeerId'] || generate_new_peer_id
        @noob_attrs['PeerId'] = @peer_id

        get_ephemeral_or_persistent_state


        case @server_state
        when StateMachine::UNREGISTERED
          # Unregistered
          case @peer_state
          when StateMachine::UNREGISTERED,
            StateMachine::WAITING_FOR_OOB,
            StateMachine::OOB_RECEIVED
            execute_param_negotiation
          else
            send_error(:state_mismatch) and return # Incompatible status
          end
        when StateMachine::WAITING_FOR_OOB
          # Waiting for OOB
          case @peer_state
          when StateMachine::UNREGISTERED
            execute_param_negotiation
          when StateMachine::WAITING_FOR_OOB
            execute_waiting
          when StateMachine::OOB_RECEIVED
            execute_noobid_discovery
          else
            send_error(:state_mismatch) and return # Incompatible status
          end
        when StateMachine::OOB_RECEIVED
          # OOB Received
          case @peer_state
          when StateMachine::UNREGISTERED
            execute_param_negotiation
          when StateMachine::WAITING_FOR_OOB
            execute_authentication_hmac
          when StateMachine::OOB_RECEIVED
            execute_noobid_discovery
          else
            send_error(:state_mismatch) and return # Incompatible status
          end
        when StateMachine::REGISTERED,
          StateMachine::RECONNECTING
          # Reconnecting/Registered
          case @peer_state
          when StateMachine::REGISTERED,
            StateMachine::RECONNECTING
            execute_reconnect_version_negotiation
          else
            send_error(:state_mismatch) and return # Incompatible status
          end
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

        send_reply return_val
      end

      # Handle Version, cryptosuite, and parameter negotiation packages
      # @param [Hash] parsed Content of the received JSON
      # @todo This is currently fixed on X25519
      def handle_param_negotiation(parsed)
        send_error(:invalid_message_structure) and return unless parsed['Verp']
        send_error(:invalid_message_structure) and return unless parsed['Cryptosuitep']
        send_error(:invalid_message_structure) and return unless parsed['Dirp']
        send_error(:invalid_message_structure) and return unless parsed['PeerInfo']

        send_error(:no_mutually_supported_version) and return if parsed['Verp'] != 1
        send_error(:no_mutually_supported_cryptosuite) and return if parsed['Cryptosuitep'] != 1

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

        send_reply return_val
      end

      # Handle ECDHE Key exchange
      # @param [Hash] parsed Content of the received JSON
      # @todo This is currently fixed on X25519
      def handle_ecdhe_exchange(parsed)
        send_error(:invalid_message_structure) and return unless parsed['PKp']
        send_error(:invalid_message_structure) and return unless parsed['Np']

        @noob_attrs['PKp'] = parsed['PKp']
        @noob_attrs['Np'] = parsed['Np']

        key_det = parsed['PKp']
        send_error(:invalid_message_structure) and return unless key_det.is_a? Hash
        # send_error(:invalid_ecdhe_key) and return unless key_det['kty'] == 'OKP'
        send_error(:invalid_ecdhe_key) and return unless key_det['crv'] == 'X25519'
        send_error(:invalid_ecdhe_key) and return unless key_det['x']

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
        oob.noob_id = @crypto.class.calculate_hash(['NoobId', noob_encoded].to_json)[0, 16]
        oob.hoob = self.class.calc_hoob(@crypto, @noob_attrs, 2, @peer_id, 0, noob_encoded)

        oob.save

        oob_msg = { peer_id: oob.peer_id, noob_id: oob.noob_id, noob: oob.noob, hoob: oob.hoob }
      end

      # Execute the Waiting exchange
      def execute_waiting
        return_val = {
          'Type': 4,
          'PeerId': @peer_id
        }
        @cur_status = :waiting_sent

        send_reply return_val
      end

      # Handle the waiting exchange
      # @param [Hash] _parsed Content of the received JSON
      def handle_waiting(_parsed)
        @eap_auth.send_failure
      end

      # Execute NoobId discovery
      def execute_noobid_discovery
        return_val = {
          'Type': 5,
          'PeerId': @peer_id
        }
        @cur_status = :noobid_discovery_sent

        send_reply return_val
      end

      # Handle NoobId discovery
      # @param [Hash] parsed Content of the received JSON
      def handle_noobid_discovery(parsed)
        send_error(:invalid_message_structure) and return unless parsed['NoobId']

        @noob = EphemeralNoob.find_by(noob_id: parsed['NoobId'])

        send_error(:unrecognized_oob_msg_identifier) and return unless @noob

        execute_authentication_hmac
      end

      # Execute the Authentication and HMAC exchange
      # @todo This is currently fixed on Curve25519
      def execute_authentication_hmac
        @noob = EphemeralNoob.where(peer_id: @peer_id).last if @server_state == StateMachine::OOB_RECEIVED && !@noob

        send_error(:application_specific_error) and return unless @noob

        @noob_attrs['KeyingMode'] = 0

        calculate_keys

        return_val = {
          'Type': 6,
          'PeerId': @peer_id,
          'NoobId': @noob.noob_id
        }
        warn 'Calc MACs'
        mac_s = Crypto::Curve25519.calculate_hmac(
          @keys['Kms'],
          Authentication.generate_hash_input(
            @noob_attrs,
            2,
            @peer_id,
            0,
            @noob.noob,
            false
          )
        )

        return_val['MACs'] = Base64.urlsafe_encode64(mac_s, padding: false)

        @cur_status = :hmac_sent

        send_reply return_val
      end

      # Handle received Authentication and HMAC exchange
      # @param [Hash] parsed Content of the received JSON
      # @todo This is currently fixed on Curve25519
      def handle_authentication_hmac(parsed)
        send_error(:invalid_message_structure) and return unless parsed['MACp']

        warn 'Calc MACp'
        mac_p = Crypto::Curve25519.calculate_hmac(
          @keys['Kmp'],
          Authentication.generate_hash_input(
            @noob_attrs,
            1,
            @peer_id,
            0,
            @noob.noob,
            false
          )
        )

        mac_p_enc = Base64.urlsafe_encode64(mac_p, padding: false)
        send_error(:hmac_verification_failure) and return unless mac_p_enc == parsed['MACp']

        save_persistent_state

        send_success
      end

      def execute_reconnect_version_negotiation
        return_val = {
          'Type': 7,
          'PeerId': @peer_id,
          'Vers': [1],
          'Cryptosuites': [1]
        }

        @noob_attrs['Vers'] = [1]
        @noob_attrs['Cryptosuites'] = [1]
        @noob_attrs['ServerInfo'] = nil

        @cur_status = :reconnect_negotiation_sent

        send_reply return_val
      end

      def handle_reconnect_version_negotiation(parsed)
        send_error(:invalid_message_structure) and return unless parsed['Verp']
        send_error(:invalid_message_structure) and return unless parsed['Cryptosuitep']

        @noob_attrs['Verp']         = parsed['Verp']
        @noob_attrs['Cryptosuitep'] = parsed['Cryptosuitep']
        # @noob_attrs['PeerInfo']     = parsed['PeerInfo'] TODO: THIS IS NOT THE RFC!!!!

        send_error(:no_mutually_supported_version) and return if parsed['Verp'] != 1
        send_error(:no_mutually_supported_cryptosuite) and return if parsed['Cryptosuitep'] != 1

        # Select the keying mode
        if @noob_attrs['Verp'] == @noob_attrs['Verp_old'] &&
           @noob_attrs['Cryptosuitep'] == @noob_attrs['Cryptosuitep_old']
          # Don't do ecdhe again, just calculate new key
          @noob_attrs['KeyingMode'] = 1
        else
          @noob_attrs['KeyingMode'] = 3
          @crypto = Crypto::Curve25519.new
        end

        execute_reconnect_ecdhe_exchange
      end

      def execute_reconnect_ecdhe_exchange
        return_val = {
          'Type': 8,
          'PeerId': @peer_id,
          'KeyingMode': @noob_attrs['KeyingMode']
        }
        if @noob_attrs['KeyingMode'] != 1
          pk_s = @crypto.pks
          @noob_attrs['PKs2'] = pk_s
          return_val['PKs2'] = pk_s
        end
        n_s = SecureRandom.random_bytes(32)
        n_s_b = Base64.urlsafe_encode64(n_s, padding: false)
        @noob_attrs['Ns2'] = n_s_b
        return_val['Ns2'] = n_s_b

        @cur_status = :reconnect_parameter_sent

        send_reply return_val
      end

      def handle_reconnect_echde_exchange(parsed)
        send_error(:invalid_message_structure) and return unless parsed['Np2']

        if @noob_attrs['KeyingMode'] != 1
          send_error(:invalid_message_structure) and return unless parsed['PKp2']

          @noob_attrs['PKp2'] = parsed['PKp2']
          key_det = parsed['PKp2']
          send_error(:invalid_message_structure) and return unless key_det.is_a? Hash
          send_error(:invalid_ecdhe_key) and return unless key_det['crv'] == 'X25519'
          send_error(:invalid_ecdhe_key) and return unless key_det['x']

          key_x = Base64.urlsafe_decode64(key_det['x'])

          @crypto.add_peer_key(key_x)

          @shared_secret = @crypto.calculate_shared_secret
        end

        @noob_attrs['Np2'] = parsed['Np2']

        execute_reconnect_hmac_exchange
      end

      def execute_reconnect_hmac_exchange

        calculate_keys(reconnect: true)

        return_val = {
          'Type': 9,
          'PeerId': @peer_id
        }
        mac_s = Crypto::Curve25519.calculate_hmac(
          @keys['Kms'],
          Authentication.generate_hash_input(
            @noob_attrs,
            2,
            @peer_id,
            @noob_attrs['KeyingMode'],
            nil,
            true
          )
        )
        return_val['MACs2'] = Base64.urlsafe_encode64(mac_s, padding: false)

        @cur_status = :reconnect_hmac_sent

        send_reply return_val
      end

      def handle_reconnect_hmac_exchange(parsed)
        send_error(:invalid_message_structure) and return unless parsed['MACp2']

        mac_p = Crypto::Curve25519.calculate_hmac(
          @keys['Kmp'],
          Authentication.generate_hash_input(
            @noob_attrs,
            1,
            @peer_id,
            @noob_attrs['KeyingMode'],
            nil,
            true
          )
        )
        mac_p_enc = Base64.urlsafe_encode64(mac_p, padding: false)
        send_error(:hmac_verification_failure) and return unless mac_p_enc == parsed['MACp2']

        save_persistent_state

        send_success
      end
      # Get the ephemeral or persistent state
      def get_ephemeral_or_persistent_state

        @persistent = PersistentState.find_by(peer_id: @peer_id)
        unless @persistent.nil?
          @shared_secret = @persistent.kz
          @noob_attrs['Kz'] = @persistent.kz
          @noob_attrs['Verp_old'] = @persistent.vers
          @noob_attrs['Cryptosuitep_old'] = @persistent.cryptosuite
          @server_state = StateMachine::REGISTERED
          return
        end

        @eph = EphemeralState.find_by(peer_id: @peer_id)
        return if @eph.nil?

        # Found an ephemeral state
        @noob_attrs = JSON.parse(@eph.noob_attrs)
        @server_state = @noob_attrs['server_state']
        @shared_secret = @eph.shared_secret

        nil
      end

      # Save the ephemeral state after the initial handshake
      def save_ephemeral_state
        state = @eph || EphemeralState.new
        state.peer_id = @peer_id
        state.noob_attrs = @noob_attrs.to_json
        state.shared_secret = @shared_secret
        state.save
      end

      # Save the persistent state after the completion/reconnect handshake
      def save_persistent_state
        # First delete all Ephemeral state associated with the peer_id
        EphemeralState.delete_by(peer_id: @peer_id)
        EphemeralNoob.delete_by(peer_id: @peer_id)
        persistent = @persistent || PersistentState.new
        persistent.kz = @keys['Kz']
        persistent.peer_id = @peer_id
        persistent.nai = @noob_attrs['NAI']
        persistent.cryptosuite = @noob_attrs['Cryptosuitep']
        persistent.vers = @noob_attrs['Verp']
        persistent.save
      end

      # Generate a new random PeerId
      # @return [String] newly allocated PeerId
      def generate_new_peer_id
        ((('a'..'z').to_a + ('0'..'9').to_a + %w[- .]) * 16).sample(16).join ''
      end

      # Derive the keys from the given inputs
      # @param [String] z Secret as byte string
      # @param [String] party_u_info PartyUInfo (Peer Nonce) as byte string
      # @param [String] party_v_info PartyVInfo (Server Nonce) as byte string
      # @param [String] supp_priv_info SuppPrivInfo (Noob/Kz) as byte string
      # @param [Integer] out_len Required number of output bytes
      # @return [String] `out_len` bytes of output
      # @todo This is currently fixed on Curve25519
      def key_generation(z, party_u_info, party_v_info, supp_priv_info, out_len)
        kdf_input = "#{z}EAP-NOOB#{party_u_info}#{party_v_info}#{supp_priv_info || ''}"
        output = ''
        ctr = 1
        puts 'KDF Input:'
        puts kdf_input.unpack1('H*')
        while output.length < out_len
          output += Crypto::Curve25519.calculate_hash([ctr].pack('N') + kdf_input)
          ctr += 1
        end
        output[0, out_len]
      end

      # Calculate the cryptographic keys
      def calculate_keys(reconnect: false)
        complete_key = key_generation(
          @shared_secret,
          Base64.urlsafe_decode64(reconnect ? @noob_attrs['Np2'] : @noob_attrs['Np']),
          Base64.urlsafe_decode64(reconnect ? @noob_attrs['Ns2'] : @noob_attrs['Ns']),
          case @noob_attrs['KeyingMode']
          when 0
            Base64.urlsafe_decode64(@noob.noob)
          when 1
            nil
            # @noob_attrs['Kz'] # TODO: THIS IS NOT THE RFC, but this is the way it is implemented in the peer.
          when 2, 3
            @noob_attrs['Kz']
          end,
          case @noob_attrs['KeyingMode']
          when 0
            320
          when 1, 2
            288
          when 3
            320
          end
        )
        puts 'Complete Key:'
        puts complete_key.unpack1('H*')
        @keys = {}
        @keys['MSK'] = complete_key[0..63]
        @keys['EMSK'] = complete_key[64..127]
        @keys['AMSK'] = complete_key[128..191]
        @keys['MethodId'] = complete_key[192..223]
        @keys['Kms'] = complete_key[224..255]
        @keys['Kmp'] = complete_key[256..287]
        @keys['Kz'] = case @noob_attrs['KeyingMode']
                      when 0, 3
                        complete_key[288..319]
                      else
                        @shared_secret
                      end
      end

      # Send Reply
      # @param [Hash] reply Content of the Reply packet as hash
      def send_reply(reply)
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    reply.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      def send_success
        @eap_auth.send_success(@keys['MSK'][0..31], @keys['MSK'][32..63])
      end
    end
  end
end
