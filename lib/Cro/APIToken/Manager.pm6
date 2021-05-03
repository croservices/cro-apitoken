use Base64;
use Crypt::Random;
use Cro::APIToken::Token;
use String::CRC32;

role X::Cro::APIToken is Exception {
    has $.token;
}

class X::Cro::APIToken::AmbiguousExpirationTime does X::Cro::APIToken {
    method message {
        'Either lifetime time or expiration date must be passed on token creation, both passed'
    }
}

class X::Cro::APIToken::TokenIsRevoked does X::Cro::APIToken {
    method message { "Token '$!token' was revoked" }
}
class X::Cro::APIToken::TokenHasExpired does X::Cro::APIToken {
    method message { "Token '$!token' has expired" }
}
class X::Cro::APIToken::TokenNotFound does X::Cro::APIToken {
    method message { "No token '$!token' found" }
}

#| Make an instance of this class in order to work with API tokens.
#| It must be created with a store named parameter, which expects an object
#| of type `Cro::APIToken::Store`; concrete implementations of this exist in
#| modules (such as `Cro::APIToken::Store::Pg`).
class Cro::APIToken::Manager {
    #| Required storage backend
    has $.store is required;
    #| Optional token prefix, used to make identifying a token easier. Default is no token prefix.
    has Str $.prefix;
    #| Whether or not to suffix the token with a CRC32 checksum. The default is `False`.
    has Bool $.checksum = False;
    #| The number of bytes worth of random data to put into the key. Defaults to 32 bytes (which are then base64-encoded).
    has Int $.bytes = 32;

    #| Creates a new API token and persists it. The %metadata holds token metadata,
    #| and should be JSON-serializable data. Use it for things like:
    #|  - Storing which user of your application the token belongs to
    #|  - Storing a set of roles that the token authorizes
    #| One of lifetime and expiration may be passed; passing both is an error.
    #| These specify how long the API token will be valid. If neither is specified, it will be valid indefinitely.
    #| Returns a `Cro::APIToken::Token` instance for the token.
    method create-token(:%metadata, Duration :$lifetime, DateTime :$expiration --> Cro::APIToken::Token) {
        die X::Cro::APIToken::AmbiguousExpirationTime.new if $lifetime && $expiration;
        my $token = self!generate-token();
        my $expr = $expiration || DateTime.new(now + $lifetime) || Nil;
        $!store.create-token($token, $expr, %metadata);
        $!store.resolve-token(self, $token);
    }

    method !generate-token(--> Str) {
        my $buf = crypt_random_buf($!bytes);
        if $!checksum {
            my $checksum = String::CRC32::crc32($buf);
            $buf.write-int32($buf.elems, $checksum, LittleEndian);
        }
        $!prefix ?? $!prefix ~ '_' ~ encode-base64($buf, :str) !! encode-base64($buf, :str);
    }

    #| Looks up the specified API token, returning a `Failure` if there is no such token.
    #| By default, if the token has been revoked or has expired, a `Failure` shall also be returned.
    #| However, passing the `:invalid` option will return such tokens also.
    method resolve-token(Str $token, Bool :$invalid = False --> Cro::APIToken::Token) {
        my Cro::APIToken::Token $token-value = $!store.resolve-token(self, $token);
        with $token-value {
            unless $invalid {
                fail X::Cro::APIToken::TokenIsRevoked.new(:$token) if $token-value.revoked;
                fail X::Cro::APIToken::TokenHasExpired.new(:$token) if $token-value.expired;
            }
            return $token-value;
        } else {
            fail X::Cro::APIToken::TokenNotFound.new(:$token);
        }
    }

    #| Used to look up tokens using metadata. Only top-level metadata keys can be looked up,
    #| and they must match by string equality. Returns a `Seq` of `Cro::APIToken::Token`.
    #| If the `:expired` option is passed then tokens that have expired will be included
    #| in the results. If the `:revoked` option is passed then tokens that have been explicitly
    #| revoked will also be returned.
    method find-tokens(:%metadata, Bool :$expired = False, Bool :$revoked --> Seq) {
        $!store.find-tokens(self, :%metadata, :$expired, :$revoked);
    }

    #| Revokes a token making it not valid anymore
    method revoke-token(Cro::APIToken::Token $token) {
        $!store.revoke-token($token);
    }
}
