require 'base64'

RSpec.describe SHA0 do
  it "has a version number" do
    expect(SHA0::VERSION).not_to be nil
  end

  it "returns hexdigest of SHA-0 hash" do
    sha = SHA0::Digest.new()
    expect(sha.hexdigest).to eq('f96cea198ad1dd5617ac084a3d92c6107708c0ef')
    expect(sha.update('abc').hexdigest).to eq('0164b8a914cd2a5e74c4f7ff082c4d97f1edf880')
    expect(sha.update('abc' * 63).hexdigest).to eq('2b7e211b5134cc340b96ac9fbb9112ebbe3114b6')
  end

  it "returns digest of SHA-0 hash" do
    sha = SHA0::Digest.new()
    expect(Base64.strict_encode64(sha.digest)).to eq('+WzqGYrR3VYXrAhKPZLGEHcIwO8=')
  end
end
