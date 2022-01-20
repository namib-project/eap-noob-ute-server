require 'json'

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
                                    { "Type": 1 }.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      def send_error(errorcode, msg=nil)

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
        when 1
          # PeerId and PeerState discovery
          send_error(nil) unless @cur_status == :new
          handle_initial(parsed)
        when 2
          # Version agreement
        else
          # Unknown or yet unsupported type
          nil
        end
      end

      private

      # Handle PeerId and PeerState discovery packages
      def handle_initial(parsed)
        @peer_state = parsed['PeerState'] || 1
        @peer_id = parsed['PeerId'] || generate_new_peer_id
        # TODO: Look up the own state based on PeerId
        case @server_state
        when 0
          # Unregistered
          if @peer_state.between?(0, 2)
            execute_initial_exchange
          else
            send_error(nil) # Incompatible status
          end
        when 1
          # Waiting for OOB
        when 2
          # OOB Received
        when 3, 4
          # Reconnecting/Registered
        end
      end

      # Executes the initial exchange
      # @todo not yet implemented
      def execute_initial_exchange
        # Not yet implemented
        return_val = {
          'Type': 2,
          'Vers': [1],
          'Cryptosuites': [1, 2],
          'Dirs': 3
        }
        return_val['PeerId'] = @peer_id
        return_val['ServerInfo'] = {
          'ServerURL': 'https://noob.namib.me/oob_submit'
        }

        @cur_status = :discovery_sent
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    @eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    return_val.to_json.unpack('C*'))
        @eap_auth.send_reply(reply_pkt)
      end

      def generate_new_peer_id
        ((('a'..'z').to_a + ('0'..'9').to_a + %w[- .]) * 16).sample(16).join ''
      end
    end
  end
end
