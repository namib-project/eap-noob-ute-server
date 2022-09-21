# frozen_string_literal: true

require 'active_record'
ActiveRecord::Base.establish_connection(
  adapter: 'sqlite3',
  database: '/tmp/eap_noob.db'
)

# Databases for EAP-NOOB

# Migration to create the Ephemeral State
class CreateEphemeralStateTable < ActiveRecord::Migration[6.1]
  def change
    create_table :ephemeral_states do |t|
      t.text :peer_id
      t.text :noob_attrs
      t.binary :shared_secret
    end
  end
end

# Migration to create the Ephemeral NOOB Database
class CreateEphemeralNoobTable < ActiveRecord::Migration[6.1]
  def change
    create_table :ephemeral_noobs do |t|
      t.text :peer_id
      t.binary :noob_id
      t.binary :noob
      t.binary :hoob
    end
  end
end

# Migration to create the Persisten State
class CreatePersistentStateTable < ActiveRecord::Migration[6.1]
  def change
    create_table :persistent_states do |t|
      t.text :peer_id
      t.binary :kz
      t.integer :vers
      t.integer :cryptosuite
      t.text :nai
    end
  end
end

# Databases for EAP-UTE

class CreateEphemeralAssociationTable < ActiveRecord::Migration[6.1]
  def change
    create_table :ephemeral_associations do |t|
      t.binary :peer_id
      t.binary :msg_hash
      t.binary :hash_input
      t.binary :shared_secret
    end
  end
end

class CreateOutOfBandTable < ActiveRecord::Migration[6.1]
  def change
    create_table :out_of_bands do |t|
      t.binary :peer_id
      t.binary :oob_id
      t.binary :nonce
      t.binary :auth
      t.integer :direction
    end
  end
end

class CreatePersistentAssociation < ActiveRecord::Migration[6.1]
  def change
    create_table :persistent_associations do |t|
      t.binary :peer_id
      t.binary :association_key
      t.integer :vers
      t.integer :cipher
    end
  end
end

CreateEphemeralStateTable.migrate(:up)
CreateEphemeralNoobTable.migrate(:up)
CreatePersistentStateTable.migrate(:up)
CreateEphemeralAssociationTable.migrate(:up)
CreateOutOfBandTable.migrate(:up)
CreatePersistentAssociation.migrate(:up)
