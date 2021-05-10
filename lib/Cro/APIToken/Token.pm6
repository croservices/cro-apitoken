#| Represents an API token.
#| Instances should always be obtained through
#| the Cro::APIToken::Manager rather than being directly constructed.
class Cro::APIToken::Token {
    has $.manager;
    #| Returns the token value
    has Str $.token is required;
    #| The metadata associated with the token.
    #| Immutable (token metadata is stored upon creation, but cannot be changed over time).
    has %.metadata;
    #| If the token expires, the DateTime of its expiration. A type object otherwise.
    has DateTime $.expiration;
    #| `True` if the token has been explicitly revoked before now.
    has Bool $.revoked = False;

    #| Returns `True` if the token has expired, `False` otherwise.
    method expired(--> Bool) {
        $!expiration ?? DateTime.now > $!expiration !! False;
    }

    #| Revokes the token, meaning it will no longer be valid.
    method revoke(--> Nil) {
        $!manager.revoke-token(self);
        $!revoked = True;
    }

    #| The object boolifies to `True` if the token is neither revoked nor expired
    #| (meaning that we can grant access to the API using it).
    #| If it has expired or been revoked, it boolifies to `False`.
    method Bool {
        not (self.expired or $!revoked);
    }
}
