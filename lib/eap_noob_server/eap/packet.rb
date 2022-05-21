# frozen_string_literal: true

module EAPNOOBServer
  module EAP
    # Error to be thrown if the EAP Packet parsing errors
    class PacketError < StandardError; end

    # EAP Packet
    # @!attribute code [rw]
    # @!attribute identifier [rw]
    # @!attribute type [rw]
    # @!attribute type_data [rw]
    # @!attribute length [r]
    class Packet
      # EAP Code
      module Code
        # EAP Code Request
        REQUEST  = 1
        # EAP Code Response
        RESPONSE = 2
        # EAP Code Success
        SUCCESS  = 3
        # EAP Code Failure
        FAILURE  = 4
      end

      # EAP Types
      module Type
        # EAP Type Identity
        IDENTITY     =  1
        # EAP Type NAK (also known as Legacy NAK)
        NAK          =  3
        # EAP Type MD5Challenge
        MD5CHALLENGE =  4
        # EAP Type TLS
        TLS          = 13
        # EAP Type TTLS
        TTLS         = 21
        # EAP Type PEAP
        PEAP         = 25
        # EAP Type MSEAP
        MSEAP        = 26
        # EAP Type FAST
        FAST         = 43
        # EAP Type PWD
        PWD          = 52
        # EAP Type NOOB
        NOOB         = 56
        # EAP Type UTE
        # @todo This is currently the EAP code for experimental EAP-Methods
        #   This should be updated once IANA issues a number for EAP-UTE
        UTE          =255

        # Get EAP Type by the given code
        # @param code [Byte] Code of the EAP Type
        # @return [String] Name of the EAP Type, or "UNKNOWN_EAPTYPE_<num>" if EAP Type is unknown
        def self.get_type_name_by_code(code)
          return nil if code.nil?

          Type.constants.each do |const|
            next if Type.const_get(const) != code

            return const.to_s
          end
          "UNKNOWN_EAPTYPE_#{code}"
        end
      end

      attr_accessor :code, :identifier, :type, :type_data
      attr_reader :length

      def initialize(code, identifier, type, type_data)
        @code = code
        @identifier = identifier
        @length = type_data.length + 5
        @type = type
        @type_data = type_data
      end

      # Recalculate the Length of the packet.
      # Resets the length attribute
      def recalc_length!
        @length = @type_data.length + 5
      end

      # Convert EAP Packet to byte array
      # @return [Array<Integer>] Bytes
      def to_bytes
        recalc_length!

        return [@code, @identifier, 0, 4] if @type.nil?

        [@code, @identifier, @length / 256, @length % 256, @type] + type_data
      end

      # Create new EAP Identity Packet
      # @param [Integer] pktid EAP PktID to use
      # @param [String] username EAP Username to use in EAP Identity Packet
      # @return [Packet] EAP Identity Packet
      def self.new_identity(pktid, username)
        Packet.new(Code::RESPONSE, pktid, Type::IDENTITY, username.unpack('C*'))
      end

      # Create new EAP NAK Packet
      # @param [Integer] pktid EAP PktID to use
      # @param [Array<Integer>] wanted_types Wanted EAP Types. Array must not be empty.
      # @return [Packet] EAP NAK Packet
      def self.new_nak(pktid, wanted_types)
        Packet.new(Code::RESPONSE, pktid, Type::NAK, wanted_types)
      end

      # Convert EAP Packet to EAPMESSAGE RADIUS Attributes
      # @return [Array<Hash>] EAPMESSAGE Attributes containing the EAP Message
      def to_radius_attributes
        bytes = to_bytes
        cur_ptr = 0
        attrs = []
        while cur_ptr < bytes.length
          attrs << { type: EAPNOOBServer::RADIUS::Packet::Attribute::EAPMESSAGE, data: bytes[cur_ptr, 253] }
          cur_ptr += 253
        end
        attrs
      end

      # Parse EAP Packet from Byte Array
      # @param [Array<Integer>] data Byte-Array
      # @return [EAPNOOBServer::EAP::Packet]
      def self.parse(data)
        code = data[0]
        identifier = data[1]
        length = data[2] * 256 + data[3]
        if length != data.length
          raise PacketError, "The coded EAP length (#{length}) does not match the actual length (#{data.length})"
        end

        type = data[4]
        type_data = data[5..-1] || []

        Packet.new(code, identifier, type, type_data)
      end

      # Parse the EAP Content from a given RADIUS Packet
      # @param [EAPNOOBServer::RADIUS::Packet] radius
      # @return [EAPNOOBServer::EAP::Packet]
      def self.parse_from_radius(radius)
        attrs = radius.get_attributes_by_type(EAPNOOBServer::RADIUS::Packet::Attribute::EAPMESSAGE)
        parse(attrs.map { |x| x[:data] }.inject([], &:+))
      end
    end
  end
end
