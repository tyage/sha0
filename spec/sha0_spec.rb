RSpec.describe SHA0 do
  it "has a version number" do
    expect(SHA0::VERSION).not_to be nil
  end

  it "hashes string with sha-0" do
    sha = SHA0::Digest.new()
    expect(sha.hexdigest).to eq('f96cea198ad1dd5617ac084a3d92c6107708c0ef')
    expect(sha.update('abc').hexdigest).to eq('0164b8a914cd2a5e74c4f7ff082c4d97f1edf880')
  end
end
