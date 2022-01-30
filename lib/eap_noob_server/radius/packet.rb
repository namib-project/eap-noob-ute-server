# frozen_string_literal: true

require 'openssl'

module EAPNOOBServer
  module RADIUS
    # Error to be thrown if anything goes wrong with the RADIUS Packet parsing.
    class PacketError < StandardError; end

    # A RADIUS Packet
    # @!attribute [rw] type
    #   @return [Integer] RADIUS Type. Codes are saved in [Radius::Packet::Type]
    # @!attribute [rw] pktid
    #   @return [Integer] Packet Identifier
    # @!attribute [rw] authenticator
    #   @return [Array<Integer>] Authenticator of the RADIUS packet
    # @!attribute [r] attributes
    #   @return [Array<Hash>] Array of Attributes. `{type: <type>, length: <length>, data: <array of bytes>}` length can be nil
    class Packet
      # Constants for RADIUS Type
      module Type
        # RADIUS Request. Sent by the NAS
        REQUEST   =  1
        # RADIUS Accept. Sent by the RADIUS-Server as final answer.
        ACCEPT    =  2
        # RADIUS Reject. Sent by the RADIUS-Server as final answer.
        REJECT    =  3
        # RADIUS Challenge. Sent by the RADIUS-Server in ongoing communication
        CHALLENGE = 11
        # RADIUS Status-Server. Sent by the NAS to check lifeness of the server
        STATUSSERVER = 12
      end

      # Constants for RADIUS Attributes
      module Attribute
        # Username. Defined by RFC2865 Section 5.1
        USERNAME                    =   1
        # User-Password. Defined by RFC2865 Section 5.2
        USERPASSWORD                =   2
        # CHAP-Password. Defined by RFC2865 Section 5.3
        CHAPPASSWORD                =   3
        # NAS-IP-Address. Defined by RFC2865 Section 5.4
        NASIPADDRESS                =   4
        # NAS-Port. Defined by RFC2865 Section 5.5
        NASPORT                     =   5
        # Service-Type. Defined by RFC2865 Section 5.6
        SERVICETYPE                 =   6
        # Framed-Protocol. Defined by RFC2865 Section 5.7
        FRAMEDPROTOCOL              =   7
        # Framed-IP-Address. Defined by RFC2865 Section 5.8
        FRAMEDIPADDRESS             =   8
        # Framed-IP-Netmask. Defined by RFC2865 Section 5.9
        FRAMEDIPNETMASK             =   9
        # Framed-Routing. Defined by RFC2865 Section 5.10
        FRAMEDROUTING               =  10
        # Filter-Id. Defined by RFC2865 Section 5.11
        FILTERID                    =  11
        # Framed-MTU. Defined by RFC2865 Section 5.12
        FRAMEDMTU                   =  12
        # Framed-Compression.  Defined by RFC2865 Section 5.13
        FRAMEDCOMPRESSION           =  13
        # Login-IP-Host. Defined by RFC2865 Section 5.14
        LOGINIPHOST                 =  14
        # Login-Service.  Defined by RFC2865 Section 5.15
        LOGINSERVICE                =  15
        # Login-TCP-Port. Defined by RFC2865 Section 5.16
        LOGINTCPPORT                =  16
        # 17 is unassigned.  Defined by RFC2865 Section 5.17
        UNASSIGNED_17               =  17
        # Reply-Message. Defined by RFC2865 Section 5.18
        REPLYMESSAGE                =  18
        # Callback-Number. Defined by RFC2865 Section 5.19
        CALLBACKNUMBER              =  19
        # Callback-Id. Defined by RFC2865 Section 5.20
        CALLBACKID                  =  20
        # 21 is unassigned.  Defined by RFC2865 Section 5.21
        UNASSIGNED_21               =  21
        # Framed-Route. Defined by RFC2865 Section 5.22
        FRAMEDROUTE                 =  22
        # Framed-IPX-Network. Defined by RFC2865 Section 5.23
        FRAMEDIPXNETWORK            =  23
        # State. Defined by RFC2865 Section 5.24
        STATE                       =  24
        # Class. Defined by RFC2865 Section 5.25
        CLASS_ATTR                  =  25
        # Vendor-Specific. Defined by RFC2865 Section 5.26
        VENDORSPECIFIC              =  26
        # Session-Timeout. Defined by RFC2865 Section 5.27
        SESSIONTIMEOUT              =  27
        # Idle-Timeout. Defined by RFC2865 Section 5.28
        IDLETIMEOUT                 =  28
        # Termination-Action. Defined by RFC2865 Section 5.29
        TERMINATIONACTION           =  29
        # Called-Station-Id. Defined by RFC2865 Section 5.30
        CALLEDSTATIONID             =  30
        # Calling-Station-Id. Defined by RFC2865 Section 5.31
        CALLINGSTATIONID            =  31
        # NAS-Identifier. Defined by RFC2865 Section 5.32
        NASIDENTIFIER               =  32
        # Proxy-State. Defined by RFC2865 Section 5.33
        PROXYSTATE                  =  33
        # Login-LAT-Service. Defined by RFC2865 Section 5.34
        LOGINLATSERVICE             =  34
        # Login-LAT-Node. Defined by RFC2865 Section 5.35
        LOGINLATNOTE                =  35
        # Login-LAT-Group. Defined by RFC2865 Section 5.36
        LOGINLATGROUP               =  36
        # Framed-AppleTalk-Link. Defined by RFC2865 Section 5.37
        FRAMEDAPPLETALKLINK         =  37
        # Framed-AppleTalk-Network. Defined by RFC2865 Section 5.38
        FRAMEDAPPLETALKNETWORK      =  38
        # Framed-AppleTalk-Zone. Defined by RFC2865 Section 5.39
        FRAMEDAPPLETALKZONE         =  39
        # Acct-Status-Type. Defined by RFC2866 Section 5.1
        ACCTSTATUSTYPE              =  40
        # Acct-Delay-Time. Defined by RFC2866 Section 5.2
        ACCTDELAYTIME               =  41
        # Acct-Input-Octets. Defined by RFC2866 Section 5.3
        ACCTINPUTOCTETS             =  42
        # Acct-Output-Octets. Defined by RFC2866 Section 5.4
        ACCTOUTPUTOCTETS            =  43
        # Acct-Session-Id. Defined by RFC2866 Section 5.5
        ACCTSESSIONID               =  44
        # Acct-Authentic. Defined by RFC2866 Section 5.6
        ACCTAUTHENTIC               =  45
        # Acct-Session-Time. Defined by RFC2866 Section 5.7
        ACCTSESSIONTIME             =  46
        # Acct-Input-Packets. Defined by RFC2866 Section 5.8
        ACCTINPUTPACKETS            =  47
        # Acct-Output-Packets. Defined by RFC2866 Section 5.9
        ACCTOUTPUTPACKETS           =  48
        # Acct-Terminate-Cause. Defined by RFC2866 Section 5.10
        ACCTTERMINATECAUSE          =  49
        # Acct-Multi-Session-Id. Defined by RFC2866 Section 5.11
        ACCTMULTISESSIONID          =  50
        # Acct-Link-Count. Defined by RFC2866 Section 5.12
        ACCTLINKCOUNT               =  51
        # Acct-Input-Gigawords. Defined by RFC2869 Section 5.1
        ACCTINPUTGIGAWORDS          =  52
        # Acct-Output-Gigawords. Defined by RFC2869 Section 5.2
        ACCTOUTPUTGIGAWORDS         =  53
        # Event-Timestamp. Defined by RFC2869 Section 5.3
        EVENTTIMESTAMP              =  55
        # CHAP-Challenge. Defined by RFC2865 Section 5.40
        CHAPCHALLENGE               =  60
        # NAS-Port-Type. Defined by RFC2865 Section 5.41
        NASPORTTYPE                 =  61
        # Port-Limit. Defined by RFC2865 Section 5.42
        PORTLIMIT                   =  62
        # Login-LAT-Port. Defined by RFC2865 Section 5.43
        LOGINLATPORT                =  63
        # Tunnel-Type. Defined by RFC2868 Section 3.1
        TUNNELTYPE                  =  64
        # Tunnel-Medium-Type. Defined by RFC2868 Section 3.2
        TUNNELMEDIUMTYPE            =  65
        # Tunnel-Client-Endpoint. Defined by RFC2868 Section 3.3
        TUNNELCLIENTENDPOINT        =  66
        # Tunnel-Server-Endpoint. Defined by RFC2868 Section 3.4
        TUNNELSERVERENDPOINT        =  67
        # Tunnel-Password. Defined by RFC2868 Section 3.5
        TUNNELPASSWORD              =  69
        # ARAP-Password. Defined by RFC2869 Section 5.4
        ARAPPASSWORD                =  70
        # ARAP-Features. Defined by RFC2869 Section 5.5
        ARAPFEATURES                =  71
        # ARAP-Zone-Access. Defined by RFC2869 Section 5.6
        ARAPZONEACCESS              =  72
        # ARAP-Security. Defined by RFC2869 Section 5.7
        ARAPSECURITY                =  73
        # ARAP-Security-Data. Defined by RFC2869 Section 5.8
        ARAPSECURITYDATA            =  74
        # Password-Retry. Defined by RFC2869 Section 5.9
        PASSWORDRETRY               =  75
        # Prompt. Defined by RFC2869 Section 5.10
        PROMPT                      =  76
        # Connect-Info. Defined by RFC2869 Section 5.11
        CONNECTINFO                 =  77
        # Configuration-Token. Defined by RFC2869 Section 5.12
        CONFIGURATIONTOKEN          =  78
        # EAP-Message. Defined by RFC2869 Section 5.13
        EAPMESSAGE                  =  79
        # Message-Authenticator. Defined by RFC2869 Section 5.14
        MESSAGEAUTHENTICATOR        =  80
        # Tunnel-Private-Group-ID. Defined RFC2868 Section 3.6
        TUNNELPRIVATEGROUPID        =  81
        # Tunnel-Assignment-ID. Defined RFC2868 Section 3.7
        TUNNELASSIGNMENTID          =  82
        # Tunnel-Preference. Defined RFC2868 Section 3.8
        TUNNELPREFERENCE            =  83
        # ARAP-Challenge-Response. Defined by RFC2869 Section 5.15
        ARAPCHALLENGERESPONSE       =  84
        # Acct-Interim-Interval. Defined by RFC2869 Section 5.16
        ACCTINTERIMINTERVAL         =  85
        # NAS-Port-Id. Defined by RFC2869 Section 5.17
        NASPORTID                   =  87
        # Framed-Pool. Defined by RFC2869 Section 5.18
        FRAMEDPOOL                  =  88
        # Chargeable User Identity. Defined by RFC4372
        CUI                         =  89
        # Tunnel-Client-Auth-ID. Defined by RFC2868 Section 3.9
        TUNNELCLIENTAUTHID          =  90
        # Tunnel-Server-Auth-ID. Defined by RFC2868 Section 3.10
        TUNNELSERVERAUTHID          =  91
        # NAS-IPv6-Address. Defined by RFC3162 Section 2.1
        NASIPV6ADDRESS              =  95
        # Framed-Interface-Id. Defined by RFC3162 Section 2.2
        FRAMEDINTERFACEID           =  96
        # Framed-IPv6-Prefix. Defined by RFC3162 Section 2.3
        FRAMEDIPV6PREFIX            =  97
        # Login-IPv6-Host. Defined by RFC3162 Section 2.4
        LOGINIPV6HOST               =  98
        # Framed-IPv6-Route. Defined by RFC3162 Section 2.5
        FRAMEDIPV6ROUTE             =  99
        # Framed-IPv6-Pool. Defined by RFC3162 Section 2.6
        FRAMEDIPV6POOL              = 100
        # EAP-Key-Name. Defined by RFC7268 Section 2.2
        EAPKEYNAME                  = 102
        # Operator-Name. Defined by RFC5580 Section 4.1
        OPERATORNAME                = 126
        # Location-Information. Defined by RFC5580 Section 4.2
        LOCATIONINFORMATION         = 127
        # Location-Data. Defined by RFC5580 Section 4.3
        LOCATIONDATA                = 128
        # Basic-Location-Policy-Rules. Defined by RFC5580 Section 4.4
        BASICLOCATIONPOLICYRULES    = 129
        # Extended-Location-Policy-Rules. Defined by RFC5580 Section 4.5
        EXTENDEDLOCATIONPOLICYRULES = 130
        # Location-Capable. Defined by RFC 5580 Section 4.6
        LOCATIONCAPABLE             = 131
        # Requested-Location-Info. Defined by RFC5580 Section 4.7
        REQUESTEDLOCATIONINFO       = 132
        # Allowed-Called-Station-Id. Defined by RFC7268 Section 2.1
        ALLOWEDCALLEDSTATIONID      = 174
        # EAP-Peer-Id. Defined by RFC7268 Section 2.3
        EAPPEERID                   = 175
        # EAP-Server-Id. Defined by RFC7268 Section 2.4
        EAPSERVERID                 = 176
        # Mobility-Domain-Id. Defined by RFC7268 Section 2.5
        MOBILITYDOMAINID            = 177
        # Preauth-Timeout. Defined by RFC7268 Section 2.6
        PREAUTHTIMEOUT              = 178
        # Network-Id-Name. Defined by RFC7268 Section 2.7
        NETWORKIDNAME               = 179
        # EAPoL-Announcement. Defined by RFC7268 Section 2.8
        EAPOLANNOUNCEMENT           = 180
        # WLAN-HESSID. Defined by RFC7268 Section 2.9
        WLANHESSID                  = 181
        # WLAN-Venue-Info. Defined by RFC7268 Section 2.10
        WLANVENUEINFO               = 182
        # WLAN-Venue-Language. Defined by RFC7268 Section 2.11
        WLANVENUELANGUAGE           = 183
        # WLAN-Venue-Name. Defined by RFC7268 Section 2.12
        WLANVENUENAME               = 184
        # WLAN-Reason-Code. Defined by RFC7268 Section 2.13
        WLANREASONCODE              = 185
        # WLAN-Pairwise-Cipher. Defined by RFC7268 Section 2.14
        WLANPAIRWISECIPHER          = 186
        # WLAN-Group-Cipher. Defined by RFC7268 Section 2.15
        WLANGROUPCIPHER             = 187
        # WLAN-AKM-Suite. Defined by RFC7268 Section 2.16
        WLANAKMSUITE                = 188
        # WLAN-Group-Mgmt-Cipher. Defined by RFC7268 Section 2.17
        WLANGROUPMGMTCIPHER         = 189
        # WLAN-RF-Band. Defined by RFC7268 Section 2.18
        WLANRFBAND                  = 190
      end

      attr_accessor :type, :pktid, :authenticator
      attr_reader :attributes

      # Create a new Packet
      # @param type [Integer] Type of the Packet
      # @param pktid [Integer] Packet Identifier
      # @param authenticator [Array<Integer>] Authenticator as Array of Bytes, may be omitted for new packet
      def initialize(type, pktid, authenticator = nil)
        @type = type
        @pktid = pktid
        @authenticator = authenticator
        @attributes = []
      end

      # Parse Packet
      # @param data [Array<Integer>] Payload of the RADIUS Packet
      # @return [RADIUS::Packet] A parsed RADIUS Packet
      def self.parse(data)
        raise PacketError, 'Packet length violates RFC2865' if data.length < 20

        type = data[0]
        pktid = data[1]
        length = data[2] * 256 + data[3]
        raise PacketError, "The length coded in the packet #{length} did not not match the actual length #{data.length}" if length != data.length

        authenticator = data[4, 16]
        pkt = Packet.new(type, pktid, authenticator)

        cur_ptr = 20
        while cur_ptr < length
          attribute = {}
          attribute[:type] = data[cur_ptr]
          attribute[:length] = data[cur_ptr + 1]
          attribute[:data] = data[cur_ptr + 2, attribute[:length] - 2]
          cur_ptr += attribute[:length]
          pkt.attributes << attribute
        end

        pkt
      end

      # Calculate Request Packet
      # @param [String] secret RADIUS Secret
      # @return [void]
      def calculate_request!(secret)
        @authenticator = (0..255).to_a.sample(16) if @authenticator.nil?

        msg_auth = get_attributes_by_type(Attribute::MESSAGEAUTHENTICATOR)
        auth_val = calc_message_authenticator(secret, @authenticator)
        if msg_auth.empty?
          @attributes << { type: Attribute::MESSAGEAUTHENTICATOR, data: auth_val }
        else
          msg_auth.first[:data] = auth_val
        end
        nil
      end

      # Add RADIUS Attributes
      # @param [Array] attrs Array of RADIUS Attributes
      def add_attributes(attrs)
        @attributes += attrs
      end

      # Calculate Reply packet
      # @param [String] secret RADIUS Secret
      # @param [Array<Integer>] request_auth Request Authenticator
      # @return [void]
      def calculate_reply!(secret, request_auth)
        msg_auth = get_attributes_by_type(Attribute::MESSAGEAUTHENTICATOR)
        auth_val = calc_message_authenticator(secret, request_auth)
        if msg_auth.empty?
          @attributes << { type: Attribute::MESSAGEAUTHENTICATOR, data: auth_val }
        else
          msg_auth.first[:data] = auth_val
        end
        @authenticator = calc_reply_packet_authenticator(secret, request_auth)
        nil
      end

      # Convert Packet information to a Byte Array
      # @param [Integer] type Packet Type (from [EAPNOOBServer::RADIUS::Packet::Type])
      # @param [Integer] pktid Packet Identifier
      # @param [Array<Integer>] authenticator Packet Authenticator Attributes
      # @param [Array<Hash>] attributes Array of Attributes
      # @return [Array<Integer>]
      def self.pkt_data_to_bytes(type, pktid, authenticator, attributes)
        attr_bytes = []
        attributes.each do |a|
          attr_bytes << a[:type]
          attr_bytes << a[:data].length + 2
          attr_bytes += a[:data]
        end

        length = attr_bytes.length + 20
        to_ret = []
        to_ret << type
        to_ret << pktid
        to_ret << length / 256
        to_ret << length % 256
        to_ret += authenticator
        to_ret += attr_bytes

        to_ret
      end

      # Convert Packet to string
      # @return [String] Packet as Bytestring to send via Socket
      def to_bytestring
        Packet.pkt_data_to_bytes(@type, @pktid, @authenticator, @attributes).pack('C*')
      end

      # Get attributes by the Attribute type
      def get_attributes_by_type(code)
        @attributes.select { |x| x[:type] == code }
      end

      # Add a vendor-specific MS-MPPE key with the correct encryption
      # @param [Integer] vendor_type 16 for Send, 17 for Recv-Key
      # @param [Array<Integer>] req_auth Request Authenticator
      # @param [String] secret RADIUS secret
      # @param [String] key Cryptographic key
      def add_cryptographic_key(vendor_type, req_auth, secret, key)
        newattr = { type: EAPNOOBServer::RADIUS::Packet::Attribute::VENDORSPECIFIC}

        # Vendor-ID Microsoft
        newattr[:data] = [0x00, 0x00, 0x01, 0x37]
        newattr[:data] += [vendor_type]

        salt = SecureRandom.random_bytes(2).unpack('C*')
        salt[0] = salt[0] | 0x80

        plaintext = [key.length] # Encode length of key
        plaintext += key.unpack('C*') # Add the key itself
        plaintext += [0] * ((16 - plaintext.length % 16) % 16) # Add padding to match 16 Byte-Blocks

        ciphertext = []
        intermediate = OpenSSL::Digest::MD5.digest(secret + req_auth.pack('C*') + salt.pack('C*')).unpack('C*')
        (0..15).each do |i|
          ciphertext[i] = plaintext[i] ^ intermediate[i]
        end
        index = 16
        while index < plaintext.length
          intermediate = OpenSSL::Digest::MD5.digest(secret + ciphertext[index - 16, 16].pack('C*')).unpack('C*')
          (0..15).each do |i|
            ciphertext[index + i] = plaintext[index + i] ^ intermediate[i]
          end
          index += 16
        end
        newattr[:data] += [ciphertext.length + 2]
        newattr[:data] += ciphertext
        @attributes << newattr
      end

      # Calculate value of the message authenticator
      # @param secret [String] RADIUS Secret
      # @param req_auth [Array<Integer>] Request Authenticator
      def calc_message_authenticator(secret, req_auth)

        # First we need to zero out the Message-Authenticator data or add an Attribute if it does not exist
        attr_copy = @attributes.clone.map(&:clone)
        auth_attr = attr_copy.filter { |x| x[:type] == Packet::Attribute::MESSAGEAUTHENTICATOR }

        raise PacketError, 'More then one Message-Authenticator Attribute was present' if auth_attr.length > 1

        if auth_attr.empty?
          attr_copy << { type: Packet::Attribute::MESSAGEAUTHENTICATOR, data: [0] * 16 }
        else
          auth_attr.first[:data] = [0] * 16
        end

        # Then we can calculate the packet bytes
        pkt_bytes = Packet.pkt_data_to_bytes(@type, @pktid, req_auth, attr_copy)

        result = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, secret, pkt_bytes.pack('C*'))

        result.unpack('C*')
      end

      # Calculate the Packet Authenticator of the Reply Packet
      # @param [String] secret RADIUS Secret
      # @param [Array<Integer>] req_auth Authenticator value of the matching Request
      # @return [Array<Integer>] The Reply Authenticator Value
      def calc_reply_packet_authenticator(secret, req_auth)
        pkt_bytes = Packet.pkt_data_to_bytes(@type, @pktid, req_auth, @attributes)
        Digest::MD5.digest(pkt_bytes.pack('C*') + secret).unpack('C*')
      end

      # Parse a request Packet
      # @param data
      # @param secret
      # @raise [PacketError]
      def self.parse_request(data, secret = nil)
        pkt = parse(data)
        unless secret.nil?
          msg_auth = pkt.calc_message_authenticator(secret, pkt.authenticator)
          msg_auth_attr = pkt.get_attributes_by_type(Packet::Attribute::MESSAGEAUTHENTICATOR)
          eap_pkts = pkt.get_attributes_by_type(Packet::Attribute::EAPMESSAGE)
          unless eap_pkts.empty?
            raise PacketError, 'No or multiple Message-Authenticator Attribute present' unless msg_auth_attr.length == 1
            raise PacketError, 'Authentication of Message Authenticator Attribute failed' unless msg_auth == msg_auth_attr.first[:data]
          end
        end
        pkt
      end

      # Parse Reply packet
      # @param [Array<Integer>] data Payload of the RADIUS Packet
      # @param secret RADIUS Secret
      # @param req_auth Request Authenticator
      # @return [Packet] Reply Packet
      # @raise [PacketError] if Message Authenticator or Packet Authenticator are invalid
      def self.parse_reply(data, secret = nil, req_auth = nil)
        pkt = parse(data)

        unless secret.nil? && req_auth.nil?
          msg_auth = pkt.calc_message_authenticator(secret, req_auth)
          msg_auth_attr = pkt.get_attributes_by_type(Packet::Attribute::MESSAGEAUTHENTICATOR)
          eap_pkts = pkt.get_attributes_by_type(Packet::Attribute::EAPMESSAGE)
          unless eap_pkts.empty?
            raise PacketError, 'No or multiple Message-Authenticator Attribute present' unless msg_auth_attr.length == 1
            raise PacketError, 'Authentication of Message Authenticator Attribute failed' unless msg_auth == msg_auth_attr.first[:data]
          end

          rad_auth = pkt.calc_reply_packet_authenticator(secret, req_auth)
          raise PacketError, 'Authentication of RADIUS Authenticator failed' unless pkt.authenticator == rad_auth
        end

        pkt
      end
    end
  end
end
