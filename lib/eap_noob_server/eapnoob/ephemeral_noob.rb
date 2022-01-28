# frozen_string_literal: true

module EAPNOOBServer
  module EAPNOOB
    # Storage Class for ephemeral noob messages
    class EphemeralNoob < ::ActiveRecord::Base
      # Create new Noob entry
      # @todo this does not yet check if a persistent state already exists
      def self.receive_noob(noob)
        st = EphemeralState.find_by(peer_id: noob['peer_id'])
        raise StandardError, 'No state for this peer id found' unless st

        attrs = JSON.parse(st.noob_attrs)

        # Check if an OOB message with the same NoobId already exists
        eph_noob = EphemeralNoob.find_by(noob_id: noob['noob_id'])
        return if eph_noob

        eph_noob = EphemeralNoob.new
        eph_noob.peer_id = noob['peer_id']
        eph_noob.noob = noob['noob']
        eph_noob.noob_id = noob['noob_id']
        eph_noob.hoob = noob['hoob']

        hoob = Base64.urlsafe_encode64(Authentication.calc_hoob(Crypto::Curve25519, attrs, 1, noob['peer_id'], 0,
                                                                noob['noob']),
                                       padding: false)

        raise StandardError, 'Hoob did not match' unless noob['hoob'] == hoob

        eph_noob.save

        attrs['server_state'] = 2
        st.noob_attrs = attrs.to_json
        st.save
      end
    end
  end
end
