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
        eph_noob = EphemeralNoob.find_by(noob_id: noob['noob_id'])
        return if eph_noob

        eph_noob = EphemeralNoob.new
        eph_noob.peer_id = noob['peer_id']
        eph_noob.noob = noob['noob']
        eph_noob.noob_id = noob['noob_id']
        eph_noob.hoob = noob['hoob]']
        eph_noob.save

        attrs['server_state'] = 2
        st.noob_attrs = attrs.to_json
        st.save
      end
    end
  end
end
