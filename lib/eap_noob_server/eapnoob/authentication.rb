require 'json'

module EAPNOOBServer
  module EAPNOOB
    class Authentication
      # Initialize a new EAP-NOOB authentication process
      # @param [String] identity NAI transmitted by the peer in the EAP-Identity message.
      # @param [EAPNOOBServer::EAP::Authentication] eap_auth
      def initialize(identity, eap_auth)
        reply_pkt = EAP::Packet.new(EAP::Packet::Code::REQUEST,
                                    eap_auth.next_identifier,
                                    EAP::Packet::Type::NOOB,
                                    { "Type": 1 }.to_json.unpack('C*'))
        eap_auth.send_reply(reply_pkt)
      end
    end
  end
end
