# frozen_string_literal: true

require 'active_record'
ActiveRecord::Base.establish_connection(
  adapter: 'sqlite3',
  database: '/tmp/eap_noob.db'
)

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

CreateEphemeralStateTable.migrate(:up)
CreateEphemeralNoobTable.migrate(:up)
CreatePersistentStateTable.migrate(:up)
