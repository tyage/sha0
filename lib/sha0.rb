require "sha0/version"
require "openssl"

K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

def rotate_left(value, shift)
  return ( ((value << shift) | (value >> (32 - shift))) & 0xffffffff)
end

module SHA0
  # Your code goes here...
  class Digest
    def initialize()
      @data = ''
      @hash = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
      ]
      @rounds = 80
      @tmp = []
      @unit_size = 4
      @block_size = 16
      @block_byte_size = @block_size * @unit_size
    end

    def update(data)
      @data += data

      while @data.size >= @block_byte_size
        block = @data[0, @block_byte_size].unpack('N*')
        process_and_update_hash(block)
        @data = @data[@block_byte_size, @data.length - @block_byte_size]
      end

      self
    end

    def padding(message)
      bit_string = message.unpack('B*')[0]
      message_length = bit_string.length
      bit_string += '1'
      while ((448 % 512) != (bit_string.length % 512)) do
        bit_string += '0'
      end
      bit_string += (('0' * (64 - message_length.to_s(2).length)) + message_length.to_s(2))
      [bit_string].pack('B*').unpack('N*')
    end

    def hexdigest()
      pad_string = padding(@data)
      new_hash = process_block(pad_string)
      new_hash.each_with_object('') do |partial, hash|
        hash << '0' * (8 - partial.to_s(16).length) + partial.to_s(16)
      end
    end

    def process_and_update_hash(block)
      @hash = process_block(block)
    end

    def process_block(block)
      working_vars = Array.new(@hash)

      @rounds.times.each do |i|
        if i < 16
          @tmp[i] = block[i]
        else
          @tmp[i] = (@tmp[i - 3] ^ @tmp[i - 8] ^ @tmp[i - 14] ^ @tmp[i - 16])
        end

        if i < 20
          f = (working_vars[1] & working_vars[2]) | (~working_vars[1] & working_vars[3])
        elsif i < 40
          f = working_vars[1] ^ working_vars[2] ^ working_vars[3]
        elsif i < 60
          f = (working_vars[1] & working_vars[2]) | (working_vars[1] & working_vars[3]) | (working_vars[2] & working_vars[3])
        else
          f = working_vars[1] ^ working_vars[2] ^ working_vars[3]
        end
        t = (rotate_left(working_vars[0], 5) + working_vars[4] + @tmp[i] + K[i / 20] + f) & 0xffffffff

        working_vars = [
          t,
          working_vars[0],
          rotate_left(working_vars[1], 30),
          working_vars[2],
          working_vars[3]
        ]
      end

      working_vars.map.with_index { |var, i|
        (@hash[i] + var) & 0xffffffff
      }
    end
  end
end
