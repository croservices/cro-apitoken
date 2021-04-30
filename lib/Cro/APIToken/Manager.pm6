use Base64;
use Crypt::Random;
use Cro::APIToken::Token;
use String::CRC32;

class Cro::APIToken::Manager {
    has $.store is required;
    has Str $.prefix;
    has Bool $.checksum = False;
    has Int $.bytes = 40;

    method create-token(:%metadata, Duration :$lifetime, DateTime :$expiration --> Cro::APIToken::Token) {
        die "Either lifetime time or expiration date must be passed on token creation"
            unless $lifetime || $expiration;
        my $token = self!generate-token();
        my $expr = $expiration ?? $expiration !! DateTime.new(now + $lifetime);
        $!store.create-token($token, $expr, %metadata // {});
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

    method resolve-token(Str $token, Bool :$invalid = False --> Cro::APIToken::Token) {
        my Cro::APIToken::Token $token-value = $!store.resolve-token(self, $token);
        with $token-value {
            unless $invalid {
                fail "Token $token was revoked" if $token-value.revoked;
                fail "Token $token has expired" if $token-value.expired;
            }
            return $token-value;
        } else {
            fail "No token '$token' found";
        }
    }

    method find-tokens(:%metadata, Bool :$expired = False, Bool :$revoked --> Seq) {
        $!store.find-tokens(self, :%metadata, :$expired, :$revoked);
    }

    method revoke($token) {
        $!store.revoke($token);
    }
}
