# SHA-0

SHA-0 implementation for Ruby.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sha0'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sha0

## Usage

```ruby
require 'sha0'

sha = SHA0::Digest.new()
puts sha.update('abc').hexdigest # '0164b8a914cd2a5e74c4f7ff082c4d97f1edf880'
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/tyage/sha0. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the SHA-0 project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/tyage/sha0/blob/master/CODE_OF_CONDUCT.md).
