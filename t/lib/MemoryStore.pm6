use Cro::APIToken::Token;
use Cro::APIToken::Manager;
use Cro::APIToken::Store;

class MemoryStore does Cro::APIToken::Store {
    has %!tokens;
    has $.manager is rw;

    method create-token(Str $token, DateTime $expiration, %metadata --> Nil) {
        %!tokens{$token} = Cro::APIToken::Token.new(:$!manager, :$token, :%metadata, :$expiration)
    }

    method find-tokens(Cro::APIToken::Manager $manager, :%metadata,
                       Bool :$expired = False, Bool :$revoked --> Seq) {
        %!tokens.values.grep(-> Cro::APIToken::Token $token {
            for %metadata.kv -> $key, $value {
                return False unless $token.metadata{$key} eq $value;
            }
            return False if $token.expired && !$expired;
            return False if $token.revoked && !$revoked;
            True;
        });
    }
    method resolve-token(Cro::APIToken::Manager $manager, Str $token --> Cro::APIToken::Token) {
        %!tokens{$token};
    }

    method revoke-token(Cro::APIToken::Token $token) {}
}
