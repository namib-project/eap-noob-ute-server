# frozen_string_literal: true

module EAPNOOBServer
  module EAP
    # EAP Authentication
    class Authentication
      attr_reader :pkt_stream, :rad_auth, :identity, :eap_noob_auth, :next_identifier

      # Initialize a new EAP Authentication Instance
      # @param [EAPNOOBServer::RADIUS::Packet] first_packet Initial RADIUS Packet
      # @param [EAPNOOBServer::RADIUS::Authentication] rad_auth Reference to the RADIUS authentication instance
      def initialize(first_packet, rad_auth)
        @rad_auth = rad_auth
        first_eap = EAP::Packet.parse_from_radius first_packet

        unless first_eap.code == EAP::Packet::Code::RESPONSE
          raise EAP::PacketError, 'The first EAP Message has to be a response'
        end
        unless first_eap.type == EAP::Packet::Type::IDENTITY
          raise EAP::PacketError, 'The first EAP Message has to be an identity'
        end

        @pkt_stream = [first_eap]
        @identity = first_eap.type_data.pack('C*')

        @next_identifier = first_eap.identifier + 1

        @eap_noob_auth = EAPNOOB::Authentication.new(@identity, self)
      end

      # Add an EAP Request
      # @param [EAPNOOBServer::RADIUS::Packet] pkt RADIUS Packet received
      # @todo Here NAKs should be handled. For now it is not implemented.
      def add_request(pkt)
        eap = EAP::Packet.parse_from_radius pkt
        unless eap.code == EAP::Packet::Code::RESPONSE
          raise EAP::PacketError, 'The EAP Message has to be a response'
        end
        unless eap.type == EAP::Packet::Type::NOOB
          raise EAP::PacketError, 'The EAP Message has to be of type EAP-NOOB'
        end
        @pkt_stream << eap

        @next_identifier = eap.identifier + 1

        @eap_noob_auth.add_request(eap)
      end

      # Send a reply to the peer.
      # @param [EAPNOOBServer::EAP::Packet] reply_pkt EAP Packet to send back
      def send_reply(reply_pkt)
        @rad_auth.send_reply(reply_pkt.to_radius_attributes)
      end
    end
  end
end
