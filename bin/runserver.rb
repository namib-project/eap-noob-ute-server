# frozen_string_literal: true

require 'irb'

require_relative '../lib/eap_noob_server'

ActiveRecord::Base.establish_connection(
  adapter: 'sqlite3',
  database: '/tmp/eap_noob.db'
)

@s = EAPNOOBServer::RADIUS::Server.new('secret')

def oob(msg)
  oobmsg = JSON.parse(Base64.decode64(msg))
  EAPNOOBServer::EAPNOOB::EphemeralNoob.receive_noob(oobmsg)
end

def oob2(peerid, noobid, noob, hoob)
  oobmsg = {
    'peer_id' => peerid,
    'noob_id' => Base64.urlsafe_encode64([noobid].pack('H*'), padding: false),
    'noob' => Base64.urlsafe_encode64([noob].pack('H*'), padding: false),
    'hoob' => Base64.urlsafe_encode64([hoob].pack('H*'), padding: false)
  }
  EAPNOOBServer::EAPNOOB::EphemeralNoob.receive_noob(oobmsg)
end

IRB.start
