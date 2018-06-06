require "sha0/version"
require "openssl"

K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

module SHA0
  # Your code goes here...
  class Digest
    def initialize()
      @data = ''
      @hash = [
        0x67452301 | 0,
        0xefcdab89 | 0,
        0x98badcfe | 0,
        0x10325476 | 0,
        0xc3d2e1f0 | 0
      ]
      @rounds = 80
      @tmp = []
    end

    def update(data)
      @data += data
    end

    def hexdigest()
      hash = OpenSSL::Digest.new('sha1')
      hash.update(@data)
      hash.hexdigest
    end

    def process_block(block)
      hash0 = @hash[0] | 0;
      hash1 = @hash[1] | 0;
      hash2 = @hash[2] | 0;
      hash3 = @hash[3] | 0;
      hash4 = @hash[4] | 0;

      @rounds.times.each do |i|
        if i < 16
          @tmp[i] = block[i] | 0
        else
          @tmp[i] = (@tmp[i - 3] ^ @tmp[i - 8] ^ @tmp[i - 14] ^ @tmp[i - 16]) | 0
        end

        t = (rotate_left(hash0, 5) + hash4 + @tmp[i] + K[i / 20]) | 0
        if i < 20
          t = (t + ((hash1 & hash2) | (~hash1 & hash3))) | 0
        elsif i < 40
          t = (t + (hash1 ^ hash2 ^ hash3)) | 0
        elsif i < 60
          t = (t + ((hash1 & hash2) | (hash1 & hash3) | (hash2 & hash3))) | 0
        else
          t = (t + (hash1 ^ hash2 ^ hash3)) | 0
        end
        hash4 = hash3
        hash3 = hash2
        hash2 = rotate_left(hash1, 30) | 0
        hash1 = hash0
        hash0 = t
      end

      @hash = [
        (@hash[0] + hash0) | 0,
        (@hash[1] + hash1) | 0,
        (@hash[2] + hash2) | 0,
        (@hash[3] + hash3) | 0,
        (@hash[4] + hash4) | 0
      ]
    end
  end
end
