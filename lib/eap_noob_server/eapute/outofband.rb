
module EAPNOOBServer
  module EAPUTE
    class OutOfBand < ::ActiveRecord::Base
      def self.receive_oob(peer_id, nonce, auth)
        state = EphemeralAssociation.find_by(peer_id: peer_id)
        raise StandardError, 'No state for this peer id found' unless state

        oob_id = OpenSSL::Digest::SHA256.digest("OOB-ID#{auth}")[0, 16]

        msg = OutOfBand.find_by(oob_id: oob_id)
        return if msg

        msg = OutOfBand.new
        msg.peer_id = peer_id
        msg.oob_id = oob_id
        msg.nonce = nonce
        msg.auth = auth
        msg.direction = 1

        hash_input = "#{state.hash_input}#{nonce}\x01"
        warn hash_input.inspect
        checkauth = OpenSSL::Digest::SHA256.digest(hash_input)

        raise StandardError, "Auth value did not match" unless checkauth == auth

        msg.save
      end
    end
  end
end
